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
	"time"

	"github.com/specterops/nemesis/titus-scanner/internal/config"
	minioclient "github.com/specterops/nemesis/titus-scanner/internal/minio"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
	"github.com/specterops/nemesis/titus-scanner/internal/scanner"
)

// Handler processes incoming Dapr pub/sub events for secret scanning.
type Handler struct {
	cfg         *config.Config
	scannerPool *scanner.Pool
	minio       *minioclient.Client
	// sem limits the number of concurrent processEvent goroutines.
	// This prevents unbounded goroutine growth (which caused OOM) while
	// still returning 200 to Dapr quickly (which prevents RabbitMQ timeouts).
	sem chan struct{}
}

// New creates a new Handler with the given configuration, scanner pool, and MinIO client.
func New(cfg *config.Config, pool *scanner.Pool, mc *minioclient.Client) *Handler {
	return &Handler{
		cfg:         cfg,
		scannerPool: pool,
		minio:       mc,
		sem:         make(chan struct{}, pool.Size()),
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

	// Process asynchronously so we return 200 to Dapr quickly. This is
	// required because synchronous processing causes RabbitMQ channel
	// timeouts on long scans, leading to message redelivery loops.
	//
	// The semaphore (sized to pool.Size()) bounds the number of in-flight
	// goroutines, preventing the OOM that unbounded goroutines caused.
	// When the semaphore is full, new goroutines block on sem acquisition
	// (not on HTTP response), so Dapr still gets its 200 immediately.
	go func() {
		h.sem <- struct{}{} // Acquire semaphore slot (blocks if full)
		defer func() { <-h.sem }()
		h.processEvent(context.Background(), input)
	}()

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

	// Scan the file — Pool.ScanFile acquires a dedicated scanner instance,
	// blocking if all instances are busy, ensuring thread-safe scanning.
	result, err := h.scannerPool.ScanFile(ctx, tmpPath, input.OriginalPath)
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
