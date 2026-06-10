package pipeline

import "testing"

import "github.com/watchvault/watchvault/internal/models"

// TestFIMSeam_IndexedDocShape pins the contract the CoreNest dashboard's FIM
// page depends on: a WatchNode FIM event must land in OpenSearch with
//
//   - event_type == "fim.<action>" (lowercase), and
//   - the collector's Fields (path, sha256, …) flattened to the TOP LEVEL.
//
// This broke once already: the dashboard queried event_type == "fim" (exact)
// and aggregated on a non-existent `action` field, so the page read zero even
// while events flowed. If the transformer stops lowercasing, or eventToDoc
// stops flattening Data to the top level, this test fails loudly in CI instead
// of silently emptying the dashboard.
func TestFIMSeam_IndexedDocShape(t *testing.T) {
	// What the WatchNode FIM collector emits (Type "fim.modified" + Fields).
	ev := &models.IndexEvent{
		Timestamp: 1_700_000_000_000,
		EventType: "FIM.Modified", // arbitrary case — transformer must normalise
		AgentName: "web01",
		Data: map[string]interface{}{
			"path":   "/etc/passwd",
			"sha256": "deadbeef",
			"action": "", // collector does NOT set a real action; suffix is the source
		},
	}

	ev = NewTransformer().Transform(ev)
	if ev.EventType != "fim.modified" {
		t.Fatalf("event_type not lowercased: got %q, want %q", ev.EventType, "fim.modified")
	}

	doc := eventToDoc(ev)

	if got := doc["event_type"]; got != "fim.modified" {
		t.Errorf("doc event_type = %v, want fim.modified", got)
	}
	// The dashboard reads `path` (normalised to file_path) at the TOP level.
	if got := doc["path"]; got != "/etc/passwd" {
		t.Errorf("doc path = %v, want /etc/passwd (Data must flatten to top level)", got)
	}
	if got := doc["sha256"]; got != "deadbeef" {
		t.Errorf("doc sha256 = %v, want deadbeef", got)
	}
	// Path must NOT be buried under a nested object the dashboard can't see.
	if _, nested := doc["data"]; nested {
		t.Errorf("Data was nested under doc[\"data\"]; dashboard expects flattened top-level fields")
	}
}
