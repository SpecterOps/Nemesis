package models

// TitusInput represents the incoming event from the Dapr pub/sub topic.
// It identifies a file in MinIO to be scanned for secrets.
type TitusInput struct {
	ObjectID     string `json:"object_id"`
	WorkflowID   string `json:"workflow_id"`
	OriginalPath string `json:"original_path"`
}

// TitusOutput represents the result published back to the Dapr output topic.
// It wraps the scan results with the original object and workflow identifiers.
type TitusOutput struct {
	ObjectID   string      `json:"object_id"`
	WorkflowID string      `json:"workflow_id"`
	ScanResult ScanResults `json:"scan_result"`
}

// ScanResults contains the complete results from scanning a file or archive.
type ScanResults struct {
	ScanDurationMs int64       `json:"scan_duration_ms"`
	BytesScanned   int64       `json:"bytes_scanned"`
	Matches        []MatchInfo `json:"matches"`
	Stats          ScanStats   `json:"stats"`
	ScanType       string      `json:"scan_type"`
}

// MatchInfo describes a single secret match found during scanning.
type MatchInfo struct {
	RuleName         string          `json:"rule_name"`
	RuleType         string          `json:"rule_type"`
	MatchedContent   string          `json:"matched_content"`
	Location         MatchLocation   `json:"location"`
	Snippet          string          `json:"snippet"`
	FilePath         *string         `json:"file_path"`
	GitCommit        *GitCommitInfo  `json:"git_commit"`
	ValidationResult *ValidationInfo `json:"validation_result,omitempty"`
}

// MatchLocation records the line and column where a match was found.
type MatchLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// GitCommitInfo holds metadata about the git commit where a match was found.
type GitCommitInfo struct {
	CommitID    string `json:"commit_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CommitDate  string `json:"commit_date"`
	Message     string `json:"message"`
}

// ScanStats contains aggregate statistics from the scan operation.
type ScanStats struct {
	BlobsSeen    int64 `json:"blobs_seen"`
	BlobsScanned int64 `json:"blobs_scanned"`
	BytesSeen    int64 `json:"bytes_seen"`
	BytesScanned int64 `json:"bytes_scanned"`
	MatchesFound int   `json:"matches_found"`
}

// ValidationInfo contains the result of validating a matched secret.
type ValidationInfo struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message,omitempty"`
}

// DaprSubscription is the response format for GET /dapr/subscribe.
// It tells the Dapr sidecar which pub/sub topics this service subscribes to.
type DaprSubscription struct {
	PubsubName string `json:"pubsubname"`
	Topic      string `json:"topic"`
	Route      string `json:"route"`
}

// DaprEvent wraps the CloudEvent envelope that Dapr sends for pub/sub messages.
type DaprEvent struct {
	Data TitusInput `json:"data"`
}

// ScanResult holds the results of scanning a file or archive.
// This is the internal representation used between the scanner and handler.
type ScanResult struct {
	BytesScanned int64
	Matches      []MatchInfo
	Stats        ScanStats
	ScanType     string // "regular", "archive", "git_repo", "error"
}
