package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/specterops/nemesis/titus-scanner/internal/config"
	"github.com/specterops/nemesis/titus-scanner/internal/models"
)

// --- mock implementations ---

type mockDownloader struct {
	fn func(ctx context.Context, objectID string, maxSizeBytes int64) (string, int64, error)
}

func (m *mockDownloader) Download(ctx context.Context, objectID string, maxSizeBytes int64) (string, int64, error) {
	return m.fn(ctx, objectID, maxSizeBytes)
}

type mockScanner struct {
	fn   func(ctx context.Context, filePath, originalPath string) (*models.ScanResult, error)
	size int
}

func (m *mockScanner) ScanFile(ctx context.Context, filePath, originalPath string) (*models.ScanResult, error) {
	return m.fn(ctx, filePath, originalPath)
}

func (m *mockScanner) Size() int { return m.size }

// --- helpers ---

func okDownloader() *mockDownloader {
	return &mockDownloader{fn: func(_ context.Context, id string, _ int64) (string, int64, error) {
		return "/tmp/fake-" + id, 1024, nil
	}}
}

func okScanner(size int) *mockScanner {
	return &mockScanner{
		fn: func(_ context.Context, _, _ string) (*models.ScanResult, error) {
			return &models.ScanResult{
				BytesScanned: 1024,
				Matches:      []models.MatchInfo{},
				Stats:        models.ScanStats{},
				ScanType:     "regular",
			}, nil
		},
		size: size,
	}
}

func testHandler(t *testing.T, dl *mockDownloader, sc *mockScanner) *Handler {
	t.Helper()
	// Fake Dapr publish endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	cfg := &config.Config{
		MaxFileSizeMB:      200,
		DaprHTTPPort:       port,
		PubsubName:         "titus",
		OutputTopic:        "titus_output",
		MaxConcurrentFiles: sc.size,
		BulkMaxMessages:    100,
	}
	return newHandler(cfg, sc, dl)
}

func entry(id, objectID string) models.BulkMessageEntry {
	return models.BulkMessageEntry{
		EntryID:     id,
		Event:       models.DaprEvent{Data: models.TitusInput{ObjectID: objectID, WorkflowID: "wf", OriginalPath: "/" + objectID}},
		ContentType: "application/cloudevents+json",
	}
}

func bulkBody(entries ...models.BulkMessageEntry) string {
	p := models.BulkMessagePayload{ID: "batch-1", Entries: entries, Topic: "titus_input"}
	b, _ := json.Marshal(p)
	return string(b)
}

func doBulk(t *testing.T, h *Handler, body string) models.BulkResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/titus_input", strings.NewReader(body))
	h.HandleBulkEvent(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp models.BulkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// --- tests ---

func TestBulk_HappyPath(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("e1", "a"), entry("e2", "b"), entry("e3", "c")))

	if len(resp.Statuses) != 3 {
		t.Fatalf("got %d statuses, want 3", len(resp.Statuses))
	}
	for i, s := range resp.Statuses {
		if s.Status != "SUCCESS" {
			t.Errorf("[%d] status = %s, want SUCCESS", i, s.Status)
		}
	}
}

func TestBulk_EmptyBatch(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody())
	if len(resp.Statuses) != 0 {
		t.Fatalf("got %d statuses, want 0", len(resp.Statuses))
	}
}

func TestBulk_MalformedJSON(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, "{bad")
	if len(resp.Statuses) != 0 {
		t.Fatalf("got %d statuses, want 0", len(resp.Statuses))
	}
}

func TestBulk_EmptyObjectID_Drop(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("e1", "")))
	if resp.Statuses[0].Status != "DROP" {
		t.Errorf("status = %s, want DROP", resp.Statuses[0].Status)
	}
}

func TestBulk_EmptyEntryID_Drop(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("", "obj-1")))
	if resp.Statuses[0].Status != "DROP" {
		t.Errorf("status = %s, want DROP", resp.Statuses[0].Status)
	}
}

func TestBulk_DuplicateEntryID_Drop(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("e1", "a"), entry("e1", "b")))
	if resp.Statuses[0].Status != "SUCCESS" {
		t.Errorf("[0] status = %s, want SUCCESS", resp.Statuses[0].Status)
	}
	if resp.Statuses[1].Status != "DROP" {
		t.Errorf("[1] status = %s, want DROP", resp.Statuses[1].Status)
	}
}

func TestBulk_MinioFailure_Retry(t *testing.T) {
	dl := &mockDownloader{fn: func(_ context.Context, _ string, _ int64) (string, int64, error) {
		return "", 0, fmt.Errorf("minio down")
	}}
	h := testHandler(t, dl, okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("e1", "obj-1")))
	if resp.Statuses[0].Status != "RETRY" {
		t.Errorf("status = %s, want RETRY", resp.Statuses[0].Status)
	}
}

func TestBulk_ScanFailure_Success(t *testing.T) {
	sc := &mockScanner{
		fn:   func(_ context.Context, _, _ string) (*models.ScanResult, error) { return nil, fmt.Errorf("corrupt") },
		size: 2,
	}
	h := testHandler(t, okDownloader(), sc)
	resp := doBulk(t, h, bulkBody(entry("e1", "obj-1")))
	// Scan errors are permanent; empty result published, entry marked SUCCESS
	if resp.Statuses[0].Status != "SUCCESS" {
		t.Errorf("status = %s, want SUCCESS (scan error is permanent)", resp.Statuses[0].Status)
	}
}

func TestBulk_PublishFailure_Retry(t *testing.T) {
	// Start a Dapr server that returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	cfg := &config.Config{
		MaxFileSizeMB:      200,
		DaprHTTPPort:       port,
		PubsubName:         "titus",
		OutputTopic:        "titus_output",
		MaxConcurrentFiles: 2,
		BulkMaxMessages:    100,
	}
	h := newHandler(cfg, okScanner(2), okDownloader())
	resp := doBulk(t, h, bulkBody(entry("e1", "obj-1")))
	if resp.Statuses[0].Status != "RETRY" {
		t.Errorf("status = %s, want RETRY", resp.Statuses[0].Status)
	}
}

func TestBulk_MixedResults(t *testing.T) {
	dl := &mockDownloader{fn: func(_ context.Context, id string, _ int64) (string, int64, error) {
		if id == "fail-dl" {
			return "", 0, fmt.Errorf("minio error")
		}
		return "/tmp/" + id, 1024, nil
	}}
	h := testHandler(t, dl, okScanner(2))
	resp := doBulk(t, h, bulkBody(
		entry("e1", "ok"),
		entry("e2", "fail-dl"),
		entry("e3", ""),         // empty object_id
		entry("e1", "ok-dupe"),  // duplicate entryId
	))

	want := []string{"SUCCESS", "RETRY", "DROP", "DROP"}
	for i, w := range want {
		if resp.Statuses[i].Status != w {
			t.Errorf("[%d] status = %s, want %s", i, resp.Statuses[i].Status, w)
		}
	}
}

func TestBulk_BoundedConcurrency(t *testing.T) {
	poolSize := 2
	var peak atomic.Int32
	var cur atomic.Int32

	dl := &mockDownloader{fn: func(_ context.Context, id string, _ int64) (string, int64, error) {
		c := cur.Add(1)
		for {
			old := peak.Load()
			if c <= old || peak.CompareAndSwap(old, c) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		return "/tmp/" + id, 1024, nil
	}}
	h := testHandler(t, dl, okScanner(poolSize))

	var entries []models.BulkMessageEntry
	for i := 0; i < 8; i++ {
		entries = append(entries, entry(fmt.Sprintf("e%d", i), fmt.Sprintf("obj-%d", i)))
	}

	resp := doBulk(t, h, bulkBody(entries...))
	for i, s := range resp.Statuses {
		if s.Status != "SUCCESS" {
			t.Errorf("[%d] status = %s, want SUCCESS", i, s.Status)
		}
	}
	if p := peak.Load(); p > int32(poolSize) {
		t.Errorf("peak concurrency = %d, exceeds pool size %d", p, poolSize)
	}
}

func TestBulk_PreservesEntryOrder(t *testing.T) {
	h := testHandler(t, okDownloader(), okScanner(2))
	resp := doBulk(t, h, bulkBody(entry("alpha", "a"), entry("beta", "b"), entry("gamma", "c")))

	ids := []string{"alpha", "beta", "gamma"}
	for i, want := range ids {
		if resp.Statuses[i].EntryID != want {
			t.Errorf("[%d] entryId = %q, want %q", i, resp.Statuses[i].EntryID, want)
		}
	}
}
