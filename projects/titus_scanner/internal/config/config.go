package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration values for the titus-scanner service.
// Values are loaded from environment variables with sensible defaults.
type Config struct {
	// Dapr pub/sub configuration
	PubsubName  string
	InputTopic  string
	OutputTopic string

	// Scanner configuration
	MaxConcurrentFiles    int
	MaxFileSizeMB         int
	MaxMatchesPerFile     int
	ExtractArchives       bool
	ExtractMaxTotalSizeMB int
	ExtractMaxFileSizeMB  int
	ExtractMaxDepth       int
	SnippetLength         int
	EnableValidation      bool
	ValidationWorkers     int
	DisabledRules         []string
	CustomRulesDir        string

	// S3-compatible storage configuration
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string

	// Bulk subscribe configuration
	BulkMaxMessages        int
	BulkMaxAwaitDurationMs int

	// Server configuration
	AppPort  string
	LogLevel string

	// Dapr HTTP port (for publishing events)
	DaprHTTPPort string
}

// Load reads configuration from environment variables, applying defaults
// where values are not set.
func Load() *Config {
	return &Config{
		PubsubName:         getEnv("PUBSUB_NAME", "titus"),
		InputTopic:         getEnv("INPUT_TOPIC", "titus_input"),
		OutputTopic:        getEnv("OUTPUT_TOPIC", "titus_output"),
		MaxConcurrentFiles:    getEnvInt("MAX_CONCURRENT_FILES", 2),
		MaxFileSizeMB:         getEnvInt("MAX_FILE_SIZE_MB", 200),
		MaxMatchesPerFile:     getEnvInt("MAX_MATCHES_PER_FILE", 500),
		ExtractArchives:       getEnvBool("EXTRACT_ARCHIVES", false),
		ExtractMaxTotalSizeMB: getEnvInt("EXTRACT_MAX_TOTAL_SIZE_MB", 1000),
		ExtractMaxFileSizeMB:  getEnvInt("EXTRACT_MAX_FILE_SIZE_MB", 10),
		ExtractMaxDepth:       getEnvInt("EXTRACT_MAX_DEPTH", 5),
		SnippetLength:      getEnvInt("SNIPPET_LENGTH", 512),
		EnableValidation:   getEnvBool("ENABLE_VALIDATION", false),
		ValidationWorkers:  getEnvInt("VALIDATION_WORKERS", 4),
		DisabledRules:      getEnvStringSlice("DISABLED_RULES"),
		CustomRulesDir:        getEnv("CUSTOM_RULES_DIR", "/opt/titus"),
		BulkMaxMessages:        max(1, getEnvInt("BULK_MAX_MESSAGES", 100)),
		BulkMaxAwaitDurationMs: max(1, getEnvInt("BULK_MAX_AWAIT_DURATION_MS", 1000)),
		S3Endpoint:      getEnv("S3_ENDPOINT", "http://seaweedfs:8333"),
		S3Bucket:        getEnv("S3_BUCKET", "files"),
		S3AccessKey:     getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:     getEnv("S3_SECRET_KEY", ""),
		AppPort:            getEnv("APP_PORT", "8080"),
		LogLevel:           getEnv("LOG_LEVEL", "info"),
		DaprHTTPPort:       getEnv("DAPR_HTTP_PORT", "3500"),
	}
}

// getEnv returns the value of the environment variable named by key,
// or defaultVal if the variable is not set or is empty.
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvInt returns the integer value of the environment variable named by key,
// or defaultVal if the variable is not set, empty, or not a valid integer.
func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return n
}

// getEnvStringSlice returns a slice of strings from a comma-separated environment
// variable. Returns nil if the variable is not set or empty.
func getEnvStringSlice(key string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// getEnvBool returns the boolean value of the environment variable named by key,
// or defaultVal if the variable is not set or empty.
// Truthy values: "true", "1", "yes" (case-insensitive).
// All other non-empty values are treated as false.
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	switch val {
	case "true", "True", "TRUE", "1", "yes", "Yes", "YES":
		return true
	default:
		return false
	}
}
