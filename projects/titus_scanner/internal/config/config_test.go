package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any env vars that might affect defaults
	envVars := []string{
		"EXTRACT_ARCHIVES", "EXTRACT_MAX_TOTAL_SIZE_MB",
		"EXTRACT_MAX_FILE_SIZE_MB", "EXTRACT_MAX_DEPTH",
		"MAX_FILE_SIZE_MB", "SNIPPET_LENGTH",
		"ENABLE_VALIDATION", "VALIDATION_WORKERS",
		"DISABLED_RULES",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	cfg := Load()

	if cfg.ExtractArchives != false {
		t.Errorf("ExtractArchives default = %v, want false", cfg.ExtractArchives)
	}
	if cfg.ExtractMaxTotalSizeMB != 1000 {
		t.Errorf("ExtractMaxTotalSizeMB default = %d, want 1000", cfg.ExtractMaxTotalSizeMB)
	}
	if cfg.ExtractMaxFileSizeMB != 10 {
		t.Errorf("ExtractMaxFileSizeMB default = %d, want 10", cfg.ExtractMaxFileSizeMB)
	}
	if cfg.ExtractMaxDepth != 5 {
		t.Errorf("ExtractMaxDepth default = %d, want 5", cfg.ExtractMaxDepth)
	}
	if cfg.MaxFileSizeMB != 200 {
		t.Errorf("MaxFileSizeMB default = %d, want 200", cfg.MaxFileSizeMB)
	}
	if cfg.SnippetLength != 512 {
		t.Errorf("SnippetLength default = %d, want 512", cfg.SnippetLength)
	}
	if cfg.EnableValidation != false {
		t.Errorf("EnableValidation default = %v, want false", cfg.EnableValidation)
	}
	if cfg.ValidationWorkers != 4 {
		t.Errorf("ValidationWorkers default = %d, want 4", cfg.ValidationWorkers)
	}
	if cfg.DisabledRules != nil {
		t.Errorf("DisabledRules default = %v, want nil", cfg.DisabledRules)
	}
}

func TestLoadDisabledRules(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		want   []string
	}{
		{"empty env", "", nil},
		{"single value", "np.linkedin.3", []string{"np.linkedin.3"}},
		{"multiple values", "np.linkedin.3,np.generic.1", []string{"np.linkedin.3", "np.generic.1"}},
		{"with spaces", " np.linkedin.3 , np.generic.1 ", []string{"np.linkedin.3", "np.generic.1"}},
		{"trailing comma", "np.linkedin.3,", []string{"np.linkedin.3"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal == "" {
				os.Unsetenv("DISABLED_RULES")
			} else {
				os.Setenv("DISABLED_RULES", tt.envVal)
				defer os.Unsetenv("DISABLED_RULES")
			}

			got := getEnvStringSlice("DISABLED_RULES")

			if tt.want == nil {
				if got != nil {
					t.Errorf("getEnvStringSlice() = %v, want nil", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("getEnvStringSlice() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getEnvStringSlice()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLoadNewEnvVars(t *testing.T) {
	os.Setenv("EXTRACT_ARCHIVES", "true")
	os.Setenv("EXTRACT_MAX_TOTAL_SIZE_MB", "500")
	os.Setenv("EXTRACT_MAX_FILE_SIZE_MB", "20")
	os.Setenv("EXTRACT_MAX_DEPTH", "3")
	defer func() {
		os.Unsetenv("EXTRACT_ARCHIVES")
		os.Unsetenv("EXTRACT_MAX_TOTAL_SIZE_MB")
		os.Unsetenv("EXTRACT_MAX_FILE_SIZE_MB")
		os.Unsetenv("EXTRACT_MAX_DEPTH")
	}()

	cfg := Load()

	if cfg.ExtractArchives != true {
		t.Errorf("ExtractArchives = %v, want true", cfg.ExtractArchives)
	}
	if cfg.ExtractMaxTotalSizeMB != 500 {
		t.Errorf("ExtractMaxTotalSizeMB = %d, want 500", cfg.ExtractMaxTotalSizeMB)
	}
	if cfg.ExtractMaxFileSizeMB != 20 {
		t.Errorf("ExtractMaxFileSizeMB = %d, want 20", cfg.ExtractMaxFileSizeMB)
	}
	if cfg.ExtractMaxDepth != 3 {
		t.Errorf("ExtractMaxDepth = %d, want 3", cfg.ExtractMaxDepth)
	}
}

func TestLoadValidationConfig(t *testing.T) {
	os.Setenv("ENABLE_VALIDATION", "true")
	os.Setenv("VALIDATION_WORKERS", "8")
	defer func() {
		os.Unsetenv("ENABLE_VALIDATION")
		os.Unsetenv("VALIDATION_WORKERS")
	}()

	cfg := Load()

	if cfg.EnableValidation != true {
		t.Errorf("EnableValidation = %v, want true", cfg.EnableValidation)
	}
	if cfg.ValidationWorkers != 8 {
		t.Errorf("ValidationWorkers = %d, want 8", cfg.ValidationWorkers)
	}
}

func TestLoadBulkDefaults(t *testing.T) {
	os.Unsetenv("BULK_MAX_MESSAGES")
	os.Unsetenv("BULK_MAX_AWAIT_DURATION_MS")

	cfg := Load()

	if cfg.BulkMaxMessages != 100 {
		t.Errorf("BulkMaxMessages default = %d, want 100", cfg.BulkMaxMessages)
	}
	if cfg.BulkMaxAwaitDurationMs != 1000 {
		t.Errorf("BulkMaxAwaitDurationMs default = %d, want 1000", cfg.BulkMaxAwaitDurationMs)
	}
}

func TestLoadBulkOverrides(t *testing.T) {
	os.Setenv("BULK_MAX_MESSAGES", "50")
	os.Setenv("BULK_MAX_AWAIT_DURATION_MS", "2000")
	defer func() {
		os.Unsetenv("BULK_MAX_MESSAGES")
		os.Unsetenv("BULK_MAX_AWAIT_DURATION_MS")
	}()

	cfg := Load()

	if cfg.BulkMaxMessages != 50 {
		t.Errorf("BulkMaxMessages = %d, want 50", cfg.BulkMaxMessages)
	}
	if cfg.BulkMaxAwaitDurationMs != 2000 {
		t.Errorf("BulkMaxAwaitDurationMs = %d, want 2000", cfg.BulkMaxAwaitDurationMs)
	}
}

func TestLoadBulkClampsToMin(t *testing.T) {
	os.Setenv("BULK_MAX_MESSAGES", "0")
	os.Setenv("BULK_MAX_AWAIT_DURATION_MS", "-5")
	defer func() {
		os.Unsetenv("BULK_MAX_MESSAGES")
		os.Unsetenv("BULK_MAX_AWAIT_DURATION_MS")
	}()

	cfg := Load()

	if cfg.BulkMaxMessages < 1 {
		t.Errorf("BulkMaxMessages = %d, want >= 1", cfg.BulkMaxMessages)
	}
	if cfg.BulkMaxAwaitDurationMs < 1 {
		t.Errorf("BulkMaxAwaitDurationMs = %d, want >= 1", cfg.BulkMaxAwaitDurationMs)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name       string
		envVal     string
		defaultVal bool
		want       bool
	}{
		{"true string", "true", false, true},
		{"True string", "True", false, true},
		{"TRUE string", "TRUE", false, true},
		{"1 string", "1", false, true},
		{"yes string", "yes", false, true},
		{"false string", "false", true, false},
		{"empty uses default true", "", true, true},
		{"empty uses default false", "", false, false},
		{"random string is false", "random", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_BOOL_VAR"
			if tt.envVal == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, tt.envVal)
				defer os.Unsetenv(key)
			}

			got := getEnvBool(key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("getEnvBool(%q, %v) with env=%q = %v, want %v",
					key, tt.defaultVal, tt.envVal, got, tt.want)
			}
		})
	}
}
