package scanner

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestGetExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"archive.tar.gz", ".tar.gz"},
		{"archive.TAR.GZ", ".tar.gz"},
		{"path/to/file.tar.gz", ".tar.gz"},
		{"archive.tgz", ".tgz"},
		{"archive.zip", ".zip"},
		{"archive.7z", ".7z"},
		{"archive.jar", ".jar"},
		{"archive.war", ".war"},
		{"archive.ear", ".ear"},
		{"archive.apk", ".apk"},
		{"archive.tar", ".tar"},
		{"file.txt", ".txt"},
		{"noext", ""},
		{"path/to/file.ZIP", ".zip"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := getExtension(tt.path)
			if got != tt.want {
				t.Errorf("getExtension(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectArchiveType_Extensions(t *testing.T) {
	tests := []struct {
		name         string
		originalPath string
		want         string
	}{
		{"zip", "test.zip", ".zip"},
		{"jar", "test.jar", ".jar"},
		{"war", "test.war", ".war"},
		{"ear", "test.ear", ".ear"},
		{"apk", "test.apk", ".apk"},
		{"ipa", "test.ipa", ".ipa"},
		{"xpi", "test.xpi", ".xpi"},
		{"crx", "test.crx", ".crx"},
		{"tar", "test.tar", ".tar"},
		{"tar.gz", "test.tar.gz", ".tar.gz"},
		{"tgz", "test.tgz", ".tgz"},
		{"7z", "test.7z", ".7z"},
		{"uppercase zip", "TEST.ZIP", ".zip"},
		{"nested path", "path/to/archive.jar", ".jar"},
	}

	emptyData := []byte{0, 0, 0, 0}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectArchiveType(tt.originalPath, emptyData)
			if got != tt.want {
				t.Errorf("detectArchiveType(%q, ...) = %q, want %q", tt.originalPath, got, tt.want)
			}
		})
	}
}

func TestDetectArchiveType_ExcludesDocuments(t *testing.T) {
	docExtensions := []string{
		"test.xlsx", "test.docx", "test.pptx",
		"test.pdf", "test.odt", "test.ods",
		"test.rtf", "test.txt", "test.csv",
	}

	emptyData := []byte{0, 0, 0, 0}

	for _, path := range docExtensions {
		t.Run(path, func(t *testing.T) {
			got := detectArchiveType(path, emptyData)
			if got != "" {
				t.Errorf("detectArchiveType(%q, ...) = %q, want empty (documents should be excluded)", path, got)
			}
		})
	}
}

func TestDetectArchiveType_MagicBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			"ZIP magic PK\\x03\\x04",
			[]byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00},
			".zip",
		},
		{
			"7z magic",
			[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x00},
			".7z",
		},
		{
			"plain gzip magic (not tar)",
			[]byte{0x1F, 0x8B, 0x08, 0x00},
			"",
		},
		{
			"gzip containing tar",
			func() []byte {
				// Build a minimal tar header inside a gzip stream
				tarHeader := make([]byte, 512)
				copy(tarHeader[257:262], "ustar")
				var buf bytes.Buffer
				w := gzip.NewWriter(&buf)
				w.Write(tarHeader)
				w.Close()
				return buf.Bytes()
			}(),
			".tar.gz",
		},
		{
			"tar magic ustar at offset 257",
			func() []byte {
				data := make([]byte, 300)
				copy(data[257:], "ustar")
				return data
			}(),
			".tar",
		},
		{
			"no magic match",
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			"",
		},
		{
			"data too short",
			[]byte{0x50, 0x4B},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pass empty originalPath to force magic byte detection
			got := detectArchiveType("", tt.data)
			if got != tt.want {
				t.Errorf("detectArchiveType(\"\", data) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectArchiveType_ExtensionTakesPrecedence(t *testing.T) {
	// ZIP magic bytes but .jar extension — should return .jar
	zipMagic := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}
	got := detectArchiveType("myapp.jar", zipMagic)
	if got != ".jar" {
		t.Errorf("detectArchiveType(\"myapp.jar\", zipMagic) = %q, want \".jar\"", got)
	}
}

func TestIsZipArchive(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"PK 03 04", []byte{0x50, 0x4B, 0x03, 0x04}, true},
		{"PK 05 06", []byte{0x50, 0x4B, 0x05, 0x06}, true},
		{"PK 07 08", []byte{0x50, 0x4B, 0x07, 0x08}, true},
		{"not zip", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"too short", []byte{0x50, 0x4B}, false},
		{"empty", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isZipArchive(tt.data)
			if got != tt.want {
				t.Errorf("isZipArchive(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestConvertValidationResult(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		got := convertValidationResult(nil)
		if got != nil {
			t.Errorf("convertValidationResult(nil) = %v, want nil", got)
		}
	})

	t.Run("valid result with all fields", func(t *testing.T) {
		ts := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
		input := &types.ValidationResult{
			Status:      types.StatusValid,
			Confidence:  0.95,
			Message:     "Token is active",
			ValidatedAt: ts,
			Details: map[string]string{
				"account_id": "123456789",
				"username":   "testuser",
			},
		}

		got := convertValidationResult(input)
		if got == nil {
			t.Fatal("convertValidationResult returned nil for non-nil input")
		}
		if got.Status != "valid" {
			t.Errorf("Status = %q, want %q", got.Status, "valid")
		}
		if got.Confidence != 0.95 {
			t.Errorf("Confidence = %f, want 0.95", got.Confidence)
		}
		if got.Message != "Token is active" {
			t.Errorf("Message = %q, want %q", got.Message, "Token is active")
		}
		if got.ValidatedAt != "2025-06-15T10:30:00Z" {
			t.Errorf("ValidatedAt = %q, want %q", got.ValidatedAt, "2025-06-15T10:30:00Z")
		}
		if len(got.Details) != 2 {
			t.Errorf("Details length = %d, want 2", len(got.Details))
		}
		if got.Details["account_id"] != "123456789" {
			t.Errorf("Details[account_id] = %q, want %q", got.Details["account_id"], "123456789")
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		input := &types.ValidationResult{
			Status:      types.StatusInvalid,
			Confidence:  1.0,
			Message:     "Token expired",
			ValidatedAt: time.Now(),
		}

		got := convertValidationResult(input)
		if got == nil {
			t.Fatal("convertValidationResult returned nil for non-nil input")
		}
		if got.Status != "invalid" {
			t.Errorf("Status = %q, want %q", got.Status, "invalid")
		}
	})

	t.Run("undetermined status", func(t *testing.T) {
		input := &types.ValidationResult{
			Status:      types.StatusUndetermined,
			Confidence:  0.0,
			ValidatedAt: time.Now(),
		}

		got := convertValidationResult(input)
		if got == nil {
			t.Fatal("convertValidationResult returned nil for non-nil input")
		}
		if got.Status != "undetermined" {
			t.Errorf("Status = %q, want %q", got.Status, "undetermined")
		}
		if got.Confidence != 0.0 {
			t.Errorf("Confidence = %f, want 0.0", got.Confidence)
		}
	})
}

func TestIsTarInGzip(t *testing.T) {
	t.Run("valid tar.gz", func(t *testing.T) {
		tarHeader := make([]byte, 512)
		copy(tarHeader[257:262], "ustar")
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(tarHeader)
		w.Close()
		if !isTarInGzip(buf.Bytes()) {
			t.Error("isTarInGzip returned false for valid tar.gz data")
		}
	})

	t.Run("plain gzip (not tar)", func(t *testing.T) {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write([]byte("this is just plain text, not a tar archive"))
		w.Close()
		if isTarInGzip(buf.Bytes()) {
			t.Error("isTarInGzip returned true for plain gzip data")
		}
	})

	t.Run("invalid gzip data", func(t *testing.T) {
		if isTarInGzip([]byte{0x1F, 0x8B, 0xFF, 0xFF}) {
			t.Error("isTarInGzip returned true for invalid gzip data")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		if isTarInGzip([]byte{}) {
			t.Error("isTarInGzip returned true for empty data")
		}
	})
}

func TestDetectArchiveType_PlainGzipFiles(t *testing.T) {
	// Regression test: plain .gz files (e.g. .kmap.gz, .psf.gz) should NOT
	// be classified as .tar.gz archives.
	tests := []struct {
		name    string
		content string
	}{
		{"small text", "hello world"},
		{"binary-like", string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			w.Write([]byte(tt.content))
			w.Close()

			got := detectArchiveType("", buf.Bytes())
			if got != "" {
				t.Errorf("detectArchiveType for plain gzip = %q, want empty string", got)
			}
		})
	}
}
