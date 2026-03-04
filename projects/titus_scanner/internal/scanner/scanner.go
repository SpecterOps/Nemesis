package scanner

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/titus"
	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
)

// Options configures the scanning behavior.
type Options struct {
	SnippetLength         int
	MaxFileSizeMB         int
	MaxMatchesPerFile     int
	ExtractArchives       bool
	ExtractMaxFileSizeMB  int
	ExtractMaxTotalSizeMB int
	ExtractMaxDepth       int
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

// archiveExtensions maps file extensions to whether they are supported archive formats.
// Document formats (xlsx, docx, pptx, pdf, etc.) are intentionally excluded
// because Nemesis handles those via the document_conversion service.
var archiveExtensions = map[string]bool{
	".zip":    true,
	".jar":    true,
	".war":    true,
	".ear":    true,
	".apk":    true,
	".ipa":    true,
	".xpi":    true,
	".crx":    true,
	".tar":    true,
	".tar.gz": true,
	".tgz":    true,
	".7z":     true,
}

// getExtension returns the file extension, with special handling for .tar.gz.
func getExtension(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") {
		return ".tar.gz"
	}
	return strings.ToLower(filepath.Ext(path))
}

// isTarInGzip decompresses the beginning of a gzip stream and checks whether
// it contains a tar archive by looking for the "ustar" magic at offset 257.
func isTarInGzip(data []byte) bool {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer r.Close()
	header := make([]byte, 263)
	n, _ := io.ReadFull(r, header)
	return n > 262 && string(header[257:262]) == "ustar"
}

// detectArchiveType determines if a file is a supported archive format.
// It checks the original path extension first, then falls back to magic byte detection.
// Returns the archive extension (e.g. ".zip", ".tar.gz") or empty string if not an archive.
func detectArchiveType(originalPath string, data []byte) string {
	// First try extension-based detection from the original path
	if originalPath != "" {
		ext := getExtension(originalPath)
		if archiveExtensions[ext] {
			return ext
		}
	}

	// Fall back to magic byte detection
	if len(data) < 4 {
		return ""
	}

	// ZIP magic: PK\x03\x04
	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		return ".zip"
	}

	// 7z magic: 7z\xBC\xAF\x27\x1C
	if len(data) >= 6 && data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC &&
		data[3] == 0xAF && data[4] == 0x27 && data[5] == 0x1C {
		return ".7z"
	}

	// Gzip magic: \x1F\x8B — only classify as .tar.gz if the gzip stream contains a tar archive
	if data[0] == 0x1F && data[1] == 0x8B {
		if isTarInGzip(data) {
			return ".tar.gz"
		}
		return ""
	}

	// TAR magic: "ustar" at offset 257
	if len(data) > 262 {
		if string(data[257:262]) == "ustar" {
			return ".tar"
		}
	}

	return ""
}

// isZipArchive checks if the data starts with a ZIP magic number.
func isZipArchive(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04) ||
		(data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x05 && data[3] == 0x06) ||
		(data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x07 && data[3] == 0x08)
}

// ScanFile scans the file at the given path, detecting whether it is a regular
// file, an archive, or contains a git repository.
func (s *Scanner) ScanFile(ctx context.Context, filePath string, originalPath string) (*models.ScanResult, error) {
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

	// Check for archive extraction
	if s.opts.ExtractArchives {
		archiveExt := detectArchiveType(originalPath, data)
		if archiveExt != "" {
			slog.Info("Detected archive file, extracting for scanning",
				"path", filePath,
				"original_path", originalPath,
				"archive_type", archiveExt,
			)

			// For ZIP-based archives, first check for git-repo-in-ZIP
			if isZipArchive(data) {
				gitResult, err := s.tryGitRepoInZip(ctx, filePath, data)
				if err == nil && gitResult != nil {
					return gitResult, nil
				}
				// Not a git repo or error checking — fall through to archive scan
			}

			return s.scanArchive(ctx, archiveExt, data)
		}
	}

	// Regular file scan
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

// tryGitRepoInZip extracts a ZIP to a temp directory and checks if it contains
// a git repository. Returns (result, nil) if a git repo was found and scanned,
// or (nil, nil) if no git repo was found.
func (s *Scanner) tryGitRepoInZip(ctx context.Context, filePath string, data []byte) (*models.ScanResult, error) {
	tmpDir, err := os.MkdirTemp("", "titus-git-check-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := s.extractZipToDir(filePath, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to extract zip for git check: %w", err)
	}

	gitDir := findGitDir(tmpDir)
	if gitDir == "" {
		return nil, nil // No git repo found
	}

	slog.Info("Found git repository in ZIP archive", "git_dir", gitDir)
	return s.scanGitRepo(ctx, filepath.Dir(gitDir))
}

// scanArchive uses the Titus library's enum.ExtractText to extract archive contents
// and scan each extracted file for secrets.
func (s *Scanner) scanArchive(ctx context.Context, archiveExt string, data []byte) (*models.ScanResult, error) {
	limits := enum.ExtractionLimits{
		MaxSize:  int64(s.opts.ExtractMaxFileSizeMB) * 1024 * 1024,
		MaxTotal: int64(s.opts.ExtractMaxTotalSizeMB) * 1024 * 1024,
		MaxDepth: s.opts.ExtractMaxDepth,
	}

	// ExtractText dispatches by file extension, so we pass "archive<ext>"
	extracted, err := enum.ExtractText("archive"+archiveExt, data, limits)
	if err != nil {
		return nil, fmt.Errorf("failed to extract archive: %w", err)
	}

	var (
		allMatches        []models.MatchInfo
		totalBytesScanned int64
		blobsScanned      int64
	)

	for _, entry := range extracted {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		entryName := entry.Name
		matches := s.scanBytes(entry.Content, &entryName, nil)
		allMatches = append(allMatches, matches...)
		totalBytesScanned += int64(len(entry.Content))
		blobsScanned++
	}

	return &models.ScanResult{
		BytesScanned: totalBytesScanned,
		Matches:      allMatches,
		Stats: models.ScanStats{
			BlobsSeen:    blobsScanned,
			BlobsScanned: blobsScanned,
			BytesSeen:    int64(len(data)),
			BytesScanned: totalBytesScanned,
			MatchesFound: len(allMatches),
		},
		ScanType: "archive",
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

	maxBytes := int64(s.opts.ExtractMaxTotalSizeMB) * 1024 * 1024
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

		maxFileBytes := int64(s.opts.ExtractMaxFileSizeMB) * 1024 * 1024
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
	scanStart := time.Now()
	titusMatches, err := s.titusScanner.ScanBytes(data)
	scanDuration := time.Since(scanStart)
	if err != nil {
		slog.Warn("Titus scan error", "error", err)
		return nil
	}
	slog.Info("Titus ScanBytes completed",
		"raw_matches", len(titusMatches),
		"scan_ms", scanDuration.Milliseconds(),
	)

	// Content-based deduplication: the Vectorscan engine deduplicates by byte
	// offset (location), so the same secret value at different positions counts
	// as separate matches (~2000+ for dense files). The portable regexp2 engine
	// deduplicates by content (ruleID + matched value), matching NoseyParker's
	// behavior (~29 matches). We apply content-based dedup here so both engines
	// produce comparable output.
	rawCount := len(titusMatches)
	seen := make(map[string]bool, len(titusMatches))
	deduped := make([]*types.Match, 0, len(titusMatches))
	for _, tm := range titusMatches {
		// Use FindingID (content-based key computed by Titus library) for dedup.
		// Falls back to RuleID + matched content if FindingID is empty.
		key := tm.FindingID
		if key == "" {
			key = tm.RuleID + "\x00" + string(tm.Snippet.Matching)
		}
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, tm)
		}
	}
	titusMatches = deduped

	if rawCount != len(titusMatches) {
		slog.Info("Content-based deduplication reduced matches",
			"raw", rawCount,
			"unique", len(titusMatches),
		)
	}

	maxMatches := s.opts.MaxMatchesPerFile
	if maxMatches <= 0 {
		maxMatches = 100
	}

	if len(titusMatches) > maxMatches {
		slog.Warn("Match count exceeds limit, truncating",
			"total_matches", len(titusMatches),
			"limit", maxMatches,
		)
		titusMatches = titusMatches[:maxMatches]
	}

	// Build line index once, then binary-search for each match (O(N + M*logN)
	// instead of O(N*M) where N=file size and M=match count).
	idx := buildLineIndex(data)

	matches := make([]models.MatchInfo, 0, len(titusMatches))

	for _, tm := range titusMatches {
		// Extract snippet — truncate Matching to avoid multi-MB payloads.
		// Hyperscan can report byte ranges spanning large regions of the file.
		matchedContent := string(tm.Snippet.Matching)
		if len(matchedContent) > s.opts.SnippetLength {
			matchedContent = matchedContent[:s.opts.SnippetLength]
		}

		snippet := fmt.Sprintf("%s[%s]%s",
			string(tm.Snippet.Before),
			matchedContent,
			string(tm.Snippet.After),
		)
		if len(snippet) > s.opts.SnippetLength*3 {
			snippet = snippet[:s.opts.SnippetLength*3]
		}

		// Titus only populates Offset (byte positions), not Source (line/column).
		// Compute line/column from the byte offset in the original content.
		line, col := idx.lineColumn(int(tm.Location.Offset.Start))

		// Derive rule type from rule ID prefix
		ruleType := "secret"

		mi := models.MatchInfo{
			RuleName:       tm.RuleName,
			RuleID:         tm.RuleID,
			RuleType:       ruleType,
			MatchedContent: matchedContent,
			Location: models.MatchLocation{
				Line:   line,
				Column: col,
			},
			Snippet:  snippet,
			FilePath: filePath,
		}

		mi.ValidationResult = convertValidationResult(tm.ValidationResult)

		if gitCommit != nil {
			commitCopy := *gitCommit
			mi.GitCommit = &commitCopy
		}

		matches = append(matches, mi)
	}

	return matches
}

// convertValidationResult converts a Titus library ValidationResult to our
// internal ValidationInfo model. Returns nil when the input is nil (validation
// disabled or no result available).
func convertValidationResult(vr *types.ValidationResult) *models.ValidationInfo {
	if vr == nil {
		return nil
	}
	return &models.ValidationInfo{
		Status:      string(vr.Status),
		Confidence:  vr.Confidence,
		Message:     vr.Message,
		ValidatedAt: vr.ValidatedAt.Format(time.RFC3339),
		Details:     vr.Details,
	}
}

// extractZipToDir safely extracts a ZIP archive to the destination directory.
// It enforces a maximum total extraction size and guards against zip-slip attacks.
// This is used only for the git-repo-in-ZIP detection path.
func (s *Scanner) extractZipToDir(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer r.Close()

	maxBytes := int64(s.opts.ExtractMaxTotalSizeMB) * 1024 * 1024
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

// lineIndex precomputes newline positions for fast offset-to-line lookups.
type lineIndex struct {
	// newlines[i] is the byte offset of the i-th newline character.
	newlines []int
}

// buildLineIndex scans data once and records all newline positions.
func buildLineIndex(data []byte) *lineIndex {
	idx := &lineIndex{}
	for i, b := range data {
		if b == '\n' {
			idx.newlines = append(idx.newlines, i)
		}
	}
	return idx
}

// lineColumn returns the 1-based line and column for a byte offset
// using binary search over the precomputed newline positions.
func (idx *lineIndex) lineColumn(offset int) (line, column int) {
	// Binary search: find how many newlines occur before offset.
	lo, hi := 0, len(idx.newlines)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if idx.newlines[mid] < offset {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	line = lo + 1 // 1-based
	if lo == 0 {
		column = offset + 1 // no newline before this offset
	} else {
		column = offset - idx.newlines[lo-1]
	}
	return line, column
}
