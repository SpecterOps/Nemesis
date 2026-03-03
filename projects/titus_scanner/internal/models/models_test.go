package models

import (
	"encoding/json"
	"testing"
)

func TestBulkMessagePayload_Unmarshal(t *testing.T) {
	// Dapr-shaped bulk subscribe payload with CloudEvent entries
	raw := `{
		"id": "bulk-req-1",
		"entries": [
			{
				"entryId": "entry-abc",
				"event": {
					"data": {"object_id": "obj-1", "workflow_id": "wf-1", "original_path": "/test"},
					"datacontenttype": "application/json",
					"id": "evt-1",
					"source": "Dapr",
					"specversion": "1.0",
					"topic": "titus_input",
					"type": "com.dapr.event.sent",
					"pubsubname": "titus"
				},
				"metadata": {"key": "val"},
				"contentType": "application/cloudevents+json"
			}
		],
		"metadata": {"pubsubName": "titus"},
		"pubsubname": "titus",
		"topic": "titus_input",
		"type": "com.dapr.event.sent.bulk"
	}`

	var payload BulkMessagePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if payload.ID != "bulk-req-1" {
		t.Errorf("ID = %q, want %q", payload.ID, "bulk-req-1")
	}
	if payload.Topic != "titus_input" {
		t.Errorf("Topic = %q, want %q", payload.Topic, "titus_input")
	}
	if len(payload.Entries) != 1 {
		t.Fatalf("len(Entries) = %d, want 1", len(payload.Entries))
	}

	e := payload.Entries[0]
	if e.EntryID != "entry-abc" {
		t.Errorf("EntryID = %q, want %q", e.EntryID, "entry-abc")
	}
	if e.ContentType != "application/cloudevents+json" {
		t.Errorf("ContentType = %q, want %q", e.ContentType, "application/cloudevents+json")
	}
	if e.Event.Data.ObjectID != "obj-1" {
		t.Errorf("ObjectID = %q, want %q", e.Event.Data.ObjectID, "obj-1")
	}
	if e.Event.Data.WorkflowID != "wf-1" {
		t.Errorf("WorkflowID = %q, want %q", e.Event.Data.WorkflowID, "wf-1")
	}
	if e.Event.Data.OriginalPath != "/test" {
		t.Errorf("OriginalPath = %q, want %q", e.Event.Data.OriginalPath, "/test")
	}
}

func TestBulkResponse_Marshal(t *testing.T) {
	resp := BulkResponse{
		Statuses: []BulkEntryStatus{
			{EntryID: "e1", Status: "SUCCESS"},
			{EntryID: "e2", Status: "RETRY"},
			{EntryID: "e3", Status: "DROP"},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Re-parse to verify key names
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	if _, ok := raw["statuses"]; !ok {
		t.Fatal("missing 'statuses' key in response JSON")
	}

	var statuses []map[string]string
	json.Unmarshal(raw["statuses"], &statuses)

	if len(statuses) != 3 {
		t.Fatalf("len(statuses) = %d, want 3", len(statuses))
	}

	for _, s := range statuses {
		if _, ok := s["entryId"]; !ok {
			t.Error("missing 'entryId' key in status entry")
		}
		if _, ok := s["status"]; !ok {
			t.Error("missing 'status' key in status entry")
		}
	}

	if statuses[0]["entryId"] != "e1" || statuses[0]["status"] != "SUCCESS" {
		t.Errorf("statuses[0] = %v, want entryId=e1/status=SUCCESS", statuses[0])
	}
	if statuses[1]["status"] != "RETRY" {
		t.Errorf("statuses[1] status = %q, want RETRY", statuses[1]["status"])
	}
	if statuses[2]["status"] != "DROP" {
		t.Errorf("statuses[2] status = %q, want DROP", statuses[2]["status"])
	}
}

func TestBulkSubscription_Marshal(t *testing.T) {
	sub := DaprBulkSubscription{
		PubsubName: "titus",
		Topic:      "titus_input",
		Route:      "/titus_input",
		BulkSubscribe: BulkSubscribeConfig{
			Enabled:            true,
			MaxMessagesCount:   100,
			MaxAwaitDurationMs: 1000,
		},
	}

	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	// Verify top-level keys
	for _, key := range []string{"pubsubname", "topic", "route", "bulkSubscribe"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in subscription JSON", key)
		}
	}

	// Verify bulkSubscribe sub-keys
	var bs map[string]json.RawMessage
	json.Unmarshal(raw["bulkSubscribe"], &bs)
	for _, key := range []string{"enabled", "maxMessagesCount", "maxAwaitDurationMs"} {
		if _, ok := bs[key]; !ok {
			t.Errorf("missing key %q in bulkSubscribe JSON", key)
		}
	}
}
