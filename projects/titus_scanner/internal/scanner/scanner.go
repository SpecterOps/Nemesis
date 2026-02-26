package scanner

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/praetorian-inc/titus"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
)

// Options configures the scanning behavior.
type Options struct {
	SnippetLength    int
	MaxFileSizeMB    int
	DecompressZips   bool
	MaxExtractSizeMB int
}

// Scanner applies secret-detection rules to file content using the Titus library.
type Scanner struct {
	titusScanner *titus.Scanner
	opts         Options
}

// New creates a Scanner with the given Titus scanner and options.
func New(ts *titus.Scanner, opts Options) *Scanner {
	if opts.SnippetLength <= 0 {
		opts.SnippetLength = 512
	}
	return &Scanner{
		titusScanner: ts,
		opts:         opts,
	}
}

// Close releases scanner resources.
func (s *Scanner) Close() error {
	if s.titusScanner != nil {
		return s.titusScanner.Close()
	}
	return nil
}

// RuleCount returns the number of loaded detection rules.
func (s *Scanner) RuleCount() int {
	if s.titusScanner != nil {
		return s.titusScanner.RuleCount()
	}
	return 0
}

// ScanFile scans the file at the given path, detecting whether it is a regular
// file, a ZIP archive, or a ZIP containing a git repository.
func (s *Scanner) ScanFile(ctx context.Context, filePath string) (*models.ScanResult, error) {
	// Check if it is a ZIP file
	if s.opts.DecompressZips && isZipFile(filePath) {
		slog.Info("Detected ZIP file, extracting for scanning", "path", filePath)
		return s.scanZip(ctx, filePath)
	}

	// Regular file scan
	return s.scanRegularFile(ctx, filePath)
}

// scanRegularFile reads a file and scans its content with the Titus scanner.
func (s *Scanner) scanRegularFile(ctx context.Context, filePath string) (*models.ScanResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	fileSize := int64(len(data))

	// Check size limit
	maxBytes := int64(s.opts.MaxFileSizeMB) * 1024 * 1024
	if fileSize > maxBytes {
		return nil, fmt.Errorf("file size %d exceeds limit %d bytes", fileSize, maxBytes)
	}

	matches := s.scanBytes(data, nil, nil)

	return &models.ScanResult{
		BytesScanned: fileSize,
		Matches:      matches,
		Stats: models.ScanStats{
			BlobsSeen:    1,
			BlobsScanned: 1,
			BytesSeen:    fileSize,
			BytesScanned: fileSize,
			MatchesFound: len(matches),
		},
		ScanType: "regular",
	}, nil
}

// scanZip extracts a ZIP archive to a temporary directory and scans its contents.
// If the archive contains a .git directory, it performs a git-aware scan.
func (s *Scanner) scanZip(ctx context.Context, zipPath string) (*models.ScanResult, error) {
	// Create temp directory for extraction
	tmpDir, err := os.MkdirTemp("", "titus-extract-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract the ZIP
	if err := s.extractZip(zipPath, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to extract zip: %w", err)
	}

	// Check if extracted content contains a git repository
	gitDir := findGitDir(tmpDir)
	if gitDir != "" {
		slog.Info("Found git repository in ZIP archive", "git_dir", gitDir)
		return s.scanGitRepo(ctx, filepath.Dir(gitDir))
	}

	// No git repo - scan all extracted files
	slog.Info("Scanning extracted ZIP contents as regular files", "dir", tmpDir)
	return s.scanDirectory(ctx, tmpDir)
}

// scanDirectory walks a directory tree and scans all regular files.
func (s *Scanner) scanDirectory(ctx context.Context, dirPath string) (*models.ScanResult, error) {
	var (
		mu                sync.Mutex
		allMatches        []models.MatchInfo
		totalBytesSeen    int64
		totalBytesScanned int64
		blobsSeen         int64
		blobsScanned      int64
	)

	maxBytes := int64(s.opts.MaxExtractSizeMB) * 1024 * 1024
	var totalExtracted int64

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			slog.Warn("Error walking directory", "path", path, "error", walkErr)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fileSize := info.Size()
		mu.Lock()
		totalExtracted += fileSize
		blobsSeen++
		totalBytesSeen += fileSize
		mu.Unlock()

		// Enforce total extraction size limit
		if totalExtracted > maxBytes {
			slog.Warn("Total extracted size exceeds limit, stopping scan",
				"total_extracted", totalExtracted,
				"limit", maxBytes,
			)
			return filepath.SkipAll
		}

		// Skip files larger than the per-file size limit
		maxFileBytes := int64(s.opts.MaxFileSizeMB) * 1024 * 1024
		if fileSize > maxFileBytes {
			slog.Debug("Skipping file exceeding size limit",
				"path", path,
				"size", fileSize,
				"limit", maxFileBytes,
			)
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("Failed to read file", "path", path, "error", err)
			return nil
		}

		// Compute relative path for the match info
		relPath, _ := filepath.Rel(dirPath, path)
		matches := s.scanBytes(data, &relPath, nil)

		mu.Lock()
		allMatches = append(allMatches, matches...)
		totalBytesScanned += int64(len(data))
		blobsScanned++
		mu.Unlock()

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return nil, fmt.Errorf("error walking directory %s: %w", dirPath, err)
	}

	return &models.ScanResult{
		BytesScanned: totalBytesScanned,
		Matches:      allMatches,
		Stats: models.ScanStats{
			BlobsSeen:    blobsSeen,
			BlobsScanned: blobsScanned,
			BytesSeen:    totalBytesSeen,
			BytesScanned: totalBytesScanned,
			MatchesFound: len(allMatches),
		},
		ScanType: "zip",
	}, nil
}

// scanGitRepo scans a git repository by walking all files in the work tree,
// skipping the .git internals directory.
func (s *Scanner) scanGitRepo(ctx context.Context, repoPath string) (*models.ScanResult, error) {
	var (
		allMatches        []models.MatchInfo
		totalBytesSeen    int64
		totalBytesScanned int64
		blobsSeen         int64
		blobsScanned      int64
	)

	maxBytes := int64(s.opts.MaxExtractSizeMB) * 1024 * 1024
	var totalScanned int64

	// Walk the work tree (all files, including untracked)
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			// Skip .git internals
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fileSize := info.Size()
		blobsSeen++
		totalBytesSeen += fileSize

		if totalScanned+fileSize > maxBytes {
			return filepath.SkipAll
		}

		maxFileBytes := int64(s.opts.MaxFileSizeMB) * 1024 * 1024
		if fileSize > maxFileBytes {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("Failed to read git file", "path", path, "error", err)
			return nil
		}

		relPath, _ := filepath.Rel(repoPath, path)
		matches := s.scanBytes(data, &relPath, nil)

		allMatches = append(allMatches, matches...)
		totalBytesScanned += int64(len(data))
		totalScanned += int64(len(data))
		blobsScanned++

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return nil, fmt.Errorf("error walking git repo %s: %w", repoPath, err)
	}

	return &models.ScanResult{
		BytesScanned: totalBytesScanned,
		Matches:      allMatches,
		Stats: models.ScanStats{
			BlobsSeen:    blobsSeen,
			BlobsScanned: blobsScanned,
			BytesSeen:    totalBytesSeen,
			BytesScanned: totalBytesScanned,
			MatchesFound: len(allMatches),
		},
		ScanType: "git_repo",
	}, nil
}

// scanBytes runs the Titus scanner against the given byte slice and converts
// matches to our output format. filePath and gitCommit are optional metadata.
func (s *Scanner) scanBytes(data []byte, filePath *string, gitCommit *models.GitCommitInfo) []models.MatchInfo {
	titusMatches, err := s.titusScanner.ScanBytes(data)
	if err != nil {
		slog.Warn("Titus scan error", "error", err)
		return nil
	}

	matches := make([]models.MatchInfo, 0, len(titusMatches))

	for _, tm := range titusMatches {
		// Extract snippet from the Titus match
		snippet := fmt.Sprintf("%s[%s]%s",
			string(tm.Snippet.Before),
			string(tm.Snippet.Matching),
			string(tm.Snippet.After),
		)

		// Titus only populates Offset (byte positions), not Source (line/column).
		// Compute line/column from the byte offset in the original content.
		line, col := computeLineColumn(data, int(tm.Location.Offset.Start))

		// Derive rule type from rule ID prefix
		ruleType := "secret"

		mi := models.MatchInfo{
			RuleName:       tm.RuleName,
			RuleType:       ruleType,
			MatchedContent: string(tm.Snippet.Matching),
			Location: models.MatchLocation{
				Line:   line,
				Column: col,
			},
			Snippet:  snippet,
			FilePath: filePath,
		}

		if gitCommit != nil {
			commitCopy := *gitCommit
			mi.GitCommit = &commitCopy
		}

		matches = append(matches, mi)
	}

	return matches
}

// extractZip safely extracts a ZIP archive to the destination directory.
// It enforces a maximum total extraction size and guards against zip-slip attacks.
func (s *Scanner) extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer r.Close()

	maxBytes := int64(s.opts.MaxExtractSizeMB) * 1024 * 1024
	var totalExtracted int64

	for _, f := range r.File {
		// Guard against zip-slip
		destPath := filepath.Join(destDir, f.Name)
		cleanDest := filepath.Clean(destPath)
		cleanDir := filepath.Clean(destDir) + string(os.PathSeparator)
		if !strings.HasPrefix(cleanDest, cleanDir) && cleanDest != filepath.Clean(destDir) {
			slog.Warn("Skipping zip entry with path traversal", "entry", f.Name)
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
			continue
		}

		// Check total extraction size
		totalExtracted += int64(f.UncompressedSize64)
		if totalExtracted > maxBytes {
			return fmt.Errorf("total extracted size %d exceeds limit %d", totalExtracted, maxBytes)
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", destPath, err)
		}

		if err := extractZipEntry(f, destPath); err != nil {
			slog.Warn("Failed to extract zip entry", "entry", f.Name, "error", err)
			continue
		}
	}

	return nil
}

// extractZipEntry extracts a single zip file entry to the given destination path.
func extractZipEntry(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to open zip entry: %w", err)
	}
	defer rc.Close()

	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("failed to write zip entry: %w", err)
	}

	return nil
}

// isZipFile checks if a file has a ZIP magic number header.
func isZipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var buf [4]byte
	n, err := f.Read(buf[:])
	if err != nil || n < 4 {
		return false
	}

	// ZIP file signatures
	return (buf[0] == 0x50 && buf[1] == 0x4B && buf[2] == 0x03 && buf[3] == 0x04) ||
		(buf[0] == 0x50 && buf[1] == 0x4B && buf[2] == 0x05 && buf[3] == 0x06) ||
		(buf[0] == 0x50 && buf[1] == 0x4B && buf[2] == 0x07 && buf[3] == 0x08)
}

// findGitDir recursively searches for a .git directory within the given root.
// Returns the full path to the .git directory if found, or empty string.
func findGitDir(root string) string {
	var result string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == ".git" {
			result = path
			return filepath.SkipAll
		}
		return nil
	})
	return result
}

// computeLineColumn computes the 1-based line and column number for a byte
// offset within the given data.
func computeLineColumn(data []byte, offset int) (line, column int) {
	if offset > len(data) {
		offset = len(data)
	}

	line = 1
	lastNewline := -1

	for i := 0; i < offset; i++ {
		if data[i] == '\n' {
			line++
			lastNewline = i
		}
	}

	column = offset - lastNewline
	return line, column
}
