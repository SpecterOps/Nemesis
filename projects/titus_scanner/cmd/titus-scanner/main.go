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

	"github.com/specterops/nemesis/titus-scanner/internal/config"
	"github.com/specterops/nemesis/titus-scanner/internal/handler"
	minioclient "github.com/specterops/nemesis/titus-scanner/internal/minio"
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
		"custom_rules_dir", cfg.CustomRulesDir,
	)

	// Load Titus builtin rules + custom rules, creating a Titus scanner
	titusScanner, ruleCount, err := rules.LoadAllRules(cfg.CustomRulesDir)
	if err != nil {
		slog.Error("Failed to load rules", "error", err)
		os.Exit(1)
	}
	slog.Info("Loaded rules", "count", ruleCount)

	// Initialize the scanner with the Titus scanner engine
	sc := scanner.New(titusScanner, scanner.Options{
		SnippetLength:         cfg.SnippetLength,
		MaxFileSizeMB:         cfg.MaxFileSizeMB,
		ExtractArchives:       cfg.ExtractArchives,
		ExtractMaxFileSizeMB:  cfg.ExtractMaxFileSizeMB,
		ExtractMaxTotalSizeMB: cfg.ExtractMaxTotalSizeMB,
		ExtractMaxDepth:       cfg.ExtractMaxDepth,
	})
	defer sc.Close()

	// Initialize MinIO client
	mc, err := minioclient.New(minioclient.Options{
		Endpoint:  cfg.MinioEndpoint,
		AccessKey: cfg.MinioAccessKey,
		SecretKey: cfg.MinioSecretKey,
		Bucket:    cfg.MinioBucket,
	})
	if err != nil {
		slog.Error("Failed to initialize MinIO client", "error", err)
		os.Exit(1)
	}
	slog.Info("MinIO client initialized", "endpoint", cfg.MinioEndpoint, "bucket", cfg.MinioBucket)

	// Create the HTTP handler
	h := handler.New(cfg, sc, mc)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Dapr subscription endpoint - tells Dapr which topics we subscribe to
	mux.HandleFunc("GET /dapr/subscribe", func(w http.ResponseWriter, r *http.Request) {
		subscriptions := []models.DaprSubscription{
			{
				PubsubName: cfg.PubsubName,
				Topic:      cfg.InputTopic,
				Route:      "/" + cfg.InputTopic,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(subscriptions); err != nil {
			slog.Error("Failed to encode subscription response", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	})

	// Event handler endpoint - receives events from Dapr pub/sub
	mux.HandleFunc("POST /"+cfg.InputTopic, h.HandleEvent)

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
