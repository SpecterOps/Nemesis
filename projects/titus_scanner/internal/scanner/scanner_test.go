package scanner

import (
	"testing"
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
			"gzip magic",
			[]byte{0x1F, 0x8B, 0x08, 0x00},
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
