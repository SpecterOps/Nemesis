package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/specterops/nemesis/titus-scanner/internal/config"
	minioclient "github.com/specterops/nemesis/titus-scanner/internal/minio"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
	"github.com/specterops/nemesis/titus-scanner/internal/scanner"
)

// Handler processes incoming Dapr pub/sub events for secret scanning.
type Handler struct {
	cfg     *config.Config
	scanner *scanner.Scanner
	minio   *minioclient.Client
	sem     chan struct{} // semaphore to limit concurrent processing
}

// New creates a new Handler with the given configuration, scanner, and MinIO client.
// It initializes a semaphore channel to enforce the maximum concurrent file limit.
func New(cfg *config.Config, sc *scanner.Scanner, mc *minioclient.Client) *Handler {
	return &Handler{
		cfg:     cfg,
		scanner: sc,
		minio:   mc,
		sem:     make(chan struct{}, cfg.MaxConcurrentFiles),
	}
}

// HandleEvent is the HTTP handler for POST /titus_input.
// It receives a Dapr CloudEvent, downloads the referenced file from MinIO,
// scans it for secrets, and publishes the results to the output topic.
func (h *Handler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	// Parse the incoming Dapr event
	var event models.DaprEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		slog.Error("Failed to decode event body", "error", err)
		// Return 200 so Dapr does not retry malformed messages
		w.WriteHeader(http.StatusOK)
		return
	}

	input := event.Data
	if input.ObjectID == "" {
		slog.Warn("Received event with empty object_id, skipping")
		w.WriteHeader(http.StatusOK)
		return
	}

	slog.Info("Received scan event",
		"object_id", input.ObjectID,
		"workflow_id", input.WorkflowID,
	)

	// Acquire semaphore slot (non-blocking check, then block)
	select {
	case h.sem <- struct{}{}:
		// Acquired immediately
	default:
		slog.Info("All processing slots busy, waiting for availability",
			"object_id", input.ObjectID,
			"max_concurrent", h.cfg.MaxConcurrentFiles,
		)
		h.sem <- struct{}{}
	}

	// Process asynchronously so we return 200 to Dapr quickly
	go func() {
		defer func() { <-h.sem }()
		h.processEvent(context.Background(), input)
	}()

	// Return success to Dapr immediately
	w.WriteHeader(http.StatusOK)
}

// processEvent handles the full lifecycle of scanning a single file:
// download, scan, and publish results.
func (h *Handler) processEvent(ctx context.Context, input models.TitusInput) {
	startTime := time.Now()

	slog.Info("Processing scan request",
		"object_id", input.ObjectID,
		"workflow_id", input.WorkflowID,
	)

	// Download the file from MinIO to a temporary location
	tmpPath, fileSize, err := h.minio.Download(ctx, input.ObjectID, int64(h.cfg.MaxFileSizeMB)*1024*1024)
	if err != nil {
		slog.Error("Failed to download file from MinIO",
			"object_id", input.ObjectID,
			"error", err,
		)
		h.publishEmptyResult(input, startTime, err.Error())
		return
	}
	defer cleanupTempFile(tmpPath)

	slog.Info("Downloaded file from MinIO",
		"object_id", input.ObjectID,
		"file_size", fileSize,
		"temp_path", tmpPath,
	)

	// Scan the file
	result, err := h.scanner.ScanFile(ctx, tmpPath)
	if err != nil {
		slog.Error("Failed to scan file",
			"object_id", input.ObjectID,
			"error", err,
		)
		h.publishEmptyResult(input, startTime, err.Error())
		return
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
	} else {
		slog.Info("Published scan result to output topic",
			"object_id", input.ObjectID,
			"topic", h.cfg.OutputTopic,
		)
	}
}

// publishResult sends the scan output to the Dapr pub/sub output topic.
func (h *Handler) publishResult(ctx context.Context, output models.TitusOutput) error {
	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

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
		return fmt.Errorf("Dapr publish returned status %d", resp.StatusCode)
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
