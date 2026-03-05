package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/praetorian-inc/titus"
	"github.com/specterops/nemesis/titus-scanner/internal/config"
	"github.com/specterops/nemesis/titus-scanner/internal/handler"
	s3client "github.com/specterops/nemesis/titus-scanner/internal/s3client"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
	"github.com/specterops/nemesis/titus-scanner/internal/rules"
	"github.com/specterops/nemesis/titus-scanner/internal/scanner"
)

func main() {
	// Load configuration from environment variables
	cfg := config.Load()

	// Configure structured logging
	initLogging(cfg.LogLevel)

	slog.Info("Starting titus-scanner service",
		"port", cfg.AppPort,
		"pubsub_name", cfg.PubsubName,
		"input_topic", cfg.InputTopic,
		"output_topic", cfg.OutputTopic,
		"max_concurrent_files", cfg.MaxConcurrentFiles,
		"max_matches_per_file", cfg.MaxMatchesPerFile,
		"custom_rules_dir", cfg.CustomRulesDir,
		"enable_validation", cfg.EnableValidation,
		"validation_workers", cfg.ValidationWorkers,
		"disabled_rules", cfg.DisabledRules,
		"bulk_max_messages", cfg.BulkMaxMessages,
		"bulk_max_await_duration_ms", cfg.BulkMaxAwaitDurationMs,
	)

	// Load all rules (builtin + custom, minus disabled)
	allRules, err := rules.LoadRules(cfg.CustomRulesDir, cfg.DisabledRules)
	if err != nil {
		slog.Error("Failed to load rules", "error", err)
		os.Exit(1)
	}
	ruleCount := len(allRules)
	slog.Info("Loaded rules", "count", ruleCount)

	// Create a pool of scanner instances — one per concurrent slot.
	// The Titus PortableRegexpMatcher is NOT safe for concurrent use,
	// so each goroutine must get its own scanner instance.
	valCfg := rules.ValidationConfig{
		EnableValidation:  cfg.EnableValidation,
		ValidationWorkers: cfg.ValidationWorkers,
	}
	scannerOpts := scanner.Options{
		SnippetLength:         cfg.SnippetLength,
		MaxFileSizeMB:         cfg.MaxFileSizeMB,
		MaxMatchesPerFile:     cfg.MaxMatchesPerFile,
		ExtractArchives:       cfg.ExtractArchives,
		ExtractMaxFileSizeMB:  cfg.ExtractMaxFileSizeMB,
		ExtractMaxTotalSizeMB: cfg.ExtractMaxTotalSizeMB,
		ExtractMaxDepth:       cfg.ExtractMaxDepth,
	}
	scannerPool, err := scanner.NewPool(cfg.MaxConcurrentFiles, scannerOpts, func() (*titus.Scanner, error) {
		return rules.CreateScanner(allRules, valCfg)
	})
	if err != nil {
		slog.Error("Failed to create scanner pool", "error", err)
		os.Exit(1)
	}
	defer scannerPool.Close()
	slog.Info("Scanner pool initialized", "size", scannerPool.Size())

	// Initialize S3 storage client
	mc, err := s3client.New(s3client.Options{
		Endpoint:  cfg.S3Endpoint,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		Bucket:    cfg.S3Bucket,
	})
	if err != nil {
		slog.Error("Failed to initialize S3 client", "error", err)
		os.Exit(1)
	}
	slog.Info("S3 client initialized", "endpoint", cfg.S3Endpoint, "bucket", cfg.S3Bucket)

	// Create the HTTP handler
	h := handler.New(cfg, scannerPool, mc)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Dapr subscription endpoint - tells Dapr which topics we subscribe to
	// with bulk subscribe enabled for batch processing.
	mux.HandleFunc("GET /dapr/subscribe", func(w http.ResponseWriter, r *http.Request) {
		subscriptions := []models.DaprBulkSubscription{
			{
				PubsubName: cfg.PubsubName,
				Topic:      cfg.InputTopic,
				Route:      "/" + cfg.InputTopic,
				BulkSubscribe: models.BulkSubscribeConfig{
					Enabled:            true,
					MaxMessagesCount:   cfg.BulkMaxMessages,
					MaxAwaitDurationMs: cfg.BulkMaxAwaitDurationMs,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(subscriptions); err != nil {
			slog.Error("Failed to encode subscription response", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})

	// Bulk event handler endpoint - receives batched events from Dapr pub/sub
	mux.HandleFunc("POST /"+cfg.InputTopic, h.HandleBulkEvent)

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","rules_loaded":%d}`, ruleCount)
	})

	// Create the HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 600 * time.Second, // Long timeout for large file scans
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		slog.Info("HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Received shutdown signal", "signal", sig)

	// Create a deadline for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server shutdown complete")
}

// initLogging configures the global slog logger based on the log level string.
func initLogging(level string) {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}
