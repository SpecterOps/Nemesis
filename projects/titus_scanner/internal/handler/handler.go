package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/specterops/nemesis/titus-scanner/internal/config"
	s3client "github.com/specterops/nemesis/titus-scanner/internal/s3client"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
	"github.com/specterops/nemesis/titus-scanner/internal/scanner"
)

// fileDownloader abstracts file downloads for testing.
type fileDownloader interface {
	Download(ctx context.Context, objectID string, maxSizeBytes int64) (string, int64, error)
}

// fileScanner abstracts file scanning for testing.
type fileScanner interface {
	ScanFile(ctx context.Context, filePath, originalPath string) (*models.ScanResult, error)
	Size() int
}

// Compile-time interface checks.
var (
	_ fileDownloader = (*s3client.Client)(nil)
	_ fileScanner    = (*scanner.Pool)(nil)
)

// Handler processes incoming Dapr bulk pub/sub events for secret scanning.
type Handler struct {
	cfg         *config.Config
	scannerPool fileScanner
	storage     fileDownloader
}

// New creates a new Handler with the given configuration, scanner pool, and S3 client.
func New(cfg *config.Config, pool *scanner.Pool, mc *s3client.Client) *Handler {
	return &Handler{
		cfg:         cfg,
		scannerPool: pool,
		storage:     mc,
	}
}

// newHandler creates a Handler with interface dependencies (used in tests).
func newHandler(cfg *config.Config, pool fileScanner, mc fileDownloader) *Handler {
	return &Handler{
		cfg:         cfg,
		scannerPool: pool,
		storage:     mc,
	}
}

// HandleBulkEvent is the HTTP handler for POST /titus_input with Dapr bulk subscribe.
// It receives a batch of entries, processes them in parallel (bounded by the scanner
// pool size), and returns per-entry statuses so Dapr knows which succeeded/failed.
func (h *Handler) HandleBulkEvent(w http.ResponseWriter, r *http.Request) {
	var payload models.BulkMessagePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Error("Failed to decode bulk event body", "error", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.BulkResponse{Statuses: []models.BulkEntryStatus{}})
		return
	}

	entries := payload.Entries
	entryCount := len(entries)
	slog.Info("Received bulk event", "batch_id", payload.ID, "entry_count", entryCount)

	if entryCount == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.BulkResponse{Statuses: []models.BulkEntryStatus{}})
		return
	}

	statuses := make([]models.BulkEntryStatus, entryCount)
	seen := make(map[string]bool, entryCount)

	// Semaphore to bound concurrent goroutines to the scanner pool size.
	sem := make(chan struct{}, h.scannerPool.Size())
	var wg sync.WaitGroup

	for i, entry := range entries {
		// Validate entryId
		if entry.EntryID == "" {
			slog.Warn("Bulk entry has empty entryId, dropping", "index", i)
			statuses[i] = models.BulkEntryStatus{EntryID: "", Status: "DROP"}
			continue
		}

		// Deduplicate by entryId
		if seen[entry.EntryID] {
			slog.Warn("Duplicate entryId in batch, dropping",
				"entry_id", entry.EntryID,
			)
			statuses[i] = models.BulkEntryStatus{EntryID: entry.EntryID, Status: "DROP"}
			continue
		}
		seen[entry.EntryID] = true

		// Validate object_id
		if entry.Event.Data.ObjectID == "" {
			slog.Warn("Bulk entry has empty object_id, dropping",
				"entry_id", entry.EntryID,
			)
			statuses[i] = models.BulkEntryStatus{EntryID: entry.EntryID, Status: "DROP"}
			continue
		}

		wg.Add(1)
		go func(idx int, e models.BulkMessageEntry) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("Panic in processEvent, marking RETRY",
						"entry_id", e.EntryID,
						"object_id", e.Event.Data.ObjectID,
						"panic", rec,
					)
					statuses[idx] = models.BulkEntryStatus{EntryID: e.EntryID, Status: "RETRY"}
				}
			}()

			sem <- struct{}{}        // Acquire semaphore slot (blocks if full)
			defer func() { <-sem }() // Release semaphore slot

			err := h.processEvent(r.Context(), e.Event.Data)
			if err != nil {
				statuses[idx] = models.BulkEntryStatus{EntryID: e.EntryID, Status: "RETRY"}
			} else {
				statuses[idx] = models.BulkEntryStatus{EntryID: e.EntryID, Status: "SUCCESS"}
			}
		}(i, entry)
	}

	wg.Wait()

	// Log batch summary
	var successes, retries, drops int
	for _, s := range statuses {
		switch s.Status {
		case "SUCCESS":
			successes++
		case "RETRY":
			retries++
		case "DROP":
			drops++
		}
	}
	slog.Info("Bulk batch complete",
		"batch_id", payload.ID,
		"total", entryCount,
		"successes", successes,
		"retries", retries,
		"drops", drops,
	)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(models.BulkResponse{Statuses: statuses}); err != nil {
		slog.Error("Failed to encode bulk response", "error", err)
	}
}

// processEvent handles the full lifecycle of scanning a single file:
// download, scan, and publish results. Returns an error for transient failures
// that should be retried (S3 download, Dapr publish). Scan failures are
// permanent — an empty result is published and nil is returned.
func (h *Handler) processEvent(ctx context.Context, input models.TitusInput) error {
	startTime := time.Now()

	slog.Info("Processing scan request",
		"object_id", input.ObjectID,
		"workflow_id", input.WorkflowID,
	)

	// Download the file from S3 storage to a temporary location
	tmpPath, fileSize, err := h.storage.Download(ctx, input.ObjectID, int64(h.cfg.MaxFileSizeMB)*1024*1024)
	if err != nil {
		slog.Error("Failed to download file from storage",
			"object_id", input.ObjectID,
			"error", err,
		)
		h.publishEmptyResult(input, startTime, err.Error())
		return fmt.Errorf("s3 download failed: %w", err)
	}
	defer cleanupTempFile(tmpPath)

	slog.Info("Downloaded file from storage",
		"object_id", input.ObjectID,
		"file_size", fileSize,
		"temp_path", tmpPath,
	)

	// Scan the file — Pool.ScanFile acquires a dedicated scanner instance,
	// blocking if all instances are busy, ensuring thread-safe scanning.
	result, err := h.scannerPool.ScanFile(ctx, tmpPath, input.OriginalPath)
	if err != nil {
		slog.Error("Failed to scan file",
			"object_id", input.ObjectID,
			"error", err,
		)
		h.publishEmptyResult(input, startTime, err.Error())
		// Scan errors are typically permanent (corrupt file, unsupported format).
		// Publish empty result so the workflow can proceed; don't retry.
		return nil
	}

	duration := time.Since(startTime)

	// Build the output
	output := models.TitusOutput{
		ObjectID:   input.ObjectID,
		WorkflowID: input.WorkflowID,
		ScanResult: models.ScanResults{
			ScanDurationMs: duration.Milliseconds(),
			BytesScanned:   result.BytesScanned,
			Matches:        result.Matches,
			Stats:          result.Stats,
			ScanType:       result.ScanType,
		},
	}

	slog.Info("Scan complete",
		"object_id", input.ObjectID,
		"duration_ms", duration.Milliseconds(),
		"matches_found", result.Stats.MatchesFound,
		"bytes_scanned", result.BytesScanned,
		"scan_type", result.ScanType,
	)

	// Publish to output topic via Dapr HTTP API
	if err := h.publishResult(ctx, output); err != nil {
		slog.Error("Failed to publish scan result",
			"object_id", input.ObjectID,
			"error", err,
		)
		return fmt.Errorf("publish failed: %w", err)
	}

	slog.Info("Published scan result to output topic",
		"object_id", input.ObjectID,
		"topic", h.cfg.OutputTopic,
	)
	return nil
}

// publishResult sends the scan output to the Dapr pub/sub output topic.
func (h *Handler) publishResult(ctx context.Context, output models.TitusOutput) error {
	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	slog.Info("Publishing scan result",
		"object_id", output.ObjectID,
		"payload_bytes", len(data),
		"match_count", len(output.ScanResult.Matches),
	)

	url := fmt.Sprintf("http://localhost:%s/v1.0/publish/%s/%s",
		h.cfg.DaprHTTPPort,
		h.cfg.PubsubName,
		h.cfg.OutputTopic,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create publish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to publish to Dapr: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("Dapr publish returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// publishEmptyResult sends an empty scan result when processing fails,
// so that downstream consumers know the scan was attempted but failed.
func (h *Handler) publishEmptyResult(input models.TitusInput, startTime time.Time, errMsg string) {
	duration := time.Since(startTime)
	output := models.TitusOutput{
		ObjectID:   input.ObjectID,
		WorkflowID: input.WorkflowID,
		ScanResult: models.ScanResults{
			ScanDurationMs: duration.Milliseconds(),
			BytesScanned:   0,
			Matches:        []models.MatchInfo{},
			Stats: models.ScanStats{
				BlobsSeen:    0,
				BlobsScanned: 0,
				BytesSeen:    0,
				BytesScanned: 0,
				MatchesFound: 0,
			},
			ScanType: "error",
		},
	}

	slog.Warn("Publishing empty result due to error",
		"object_id", input.ObjectID,
		"error", errMsg,
	)

	if err := h.publishResult(context.Background(), output); err != nil {
		slog.Error("Failed to publish empty result",
			"object_id", input.ObjectID,
			"error", err,
		)
	}
}

// cleanupTempFile removes a temporary file or directory, logging any error.
func cleanupTempFile(path string) {
	if err := os.RemoveAll(path); err != nil {
		slog.Warn("Failed to clean up temporary file", "path", path, "error", err)
	}
}
