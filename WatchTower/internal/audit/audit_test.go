package audit

import (
	"sync"
	"testing"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// mockSink captures events for assertions.
type mockSink struct {
	mu     sync.Mutex
	events []*models.Event
}

func (s *mockSink) Ingest(e *models.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *mockSink) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.events))
	for _, e := range s.events {
		rec := Record{
			ID:            e.ID,
			Timestamp:     e.Timestamp,
			EventType:     EventType(e.Fields["event_type"].(string)),
			Success:       e.Fields["success"].(bool),
			PrevHash:      e.Fields["prev_hash"].(string),
			RecordHash:    e.Fields["record_hash"].(string),
			HMACSignature: e.Fields["hmac_signature"].(string),
		}
		if v, ok := e.Fields["actor_ip"]; ok {
			rec.ActorIP, _ = v.(string)
		}
		if v, ok := e.Fields["path"]; ok {
			rec.Path, _ = v.(string)
		}
		out = append(out, rec)
	}
	return out
}

func TestAuditChainLinksConsecutiveRecords(t *testing.T) {
	sink := &mockSink{}
	key := []byte("test-signing-key-32-bytes-long!!!")
	l := New(sink, key, zap.NewNop())

	l.Log(Record{EventType: EventTypeAPICall, Path: "/a", Success: true})
	l.Log(Record{EventType: EventTypeAPICall, Path: "/b", Success: true})
	l.Log(Record{EventType: EventTypeAPICall, Path: "/c", Success: false})

	recs := sink.Records()
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
	if recs[0].PrevHash != "" {
		t.Errorf("first record must have empty PrevHash, got %q", recs[0].PrevHash)
	}
	if recs[1].PrevHash != recs[0].RecordHash {
		t.Errorf("record 2 PrevHash mismatch: got %q want %q", recs[1].PrevHash, recs[0].RecordHash)
	}
	if recs[2].PrevHash != recs[1].RecordHash {
		t.Errorf("record 3 PrevHash mismatch: got %q want %q", recs[2].PrevHash, recs[1].RecordHash)
	}
}

func TestVerifyRecordDetectsTampering(t *testing.T) {
	sink := &mockSink{}
	key := []byte("test-signing-key-32-bytes-long!!!")
	l := New(sink, key, zap.NewNop())
	l.Log(Record{EventType: EventTypeAPICall, Path: "/original", Success: true})

	rec := sink.Records()[0]

	// Honest record verifies.
	hashOK, hmacOK := VerifyRecord(&rec, "", key)
	if !hashOK || !hmacOK {
		t.Errorf("honest record failed verification: hashOK=%v hmacOK=%v", hashOK, hmacOK)
	}

	// Tampering with the path breaks the hash (forged record).
	tampered := rec
	tampered.Path = "/forged"
	hashOK, _ = VerifyRecord(&tampered, "", key)
	if hashOK {
		t.Error("tampered record should fail hash verification")
	}
}

func TestVerifyRecordWithWrongKeyFailsHMAC(t *testing.T) {
	sink := &mockSink{}
	correctKey := []byte("correct-key-32-bytes-long!!!12345")
	wrongKey := []byte("wrong-key-32-bytes-long!!!12345678")
	l := New(sink, correctKey, zap.NewNop())
	l.Log(Record{EventType: EventTypeAPICall, Path: "/x", Success: true})

	rec := sink.Records()[0]
	hashOK, hmacOK := VerifyRecord(&rec, "", wrongKey)
	if !hashOK {
		t.Error("hash should verify even without key (it's a plain hash)")
	}
	if hmacOK {
		t.Error("HMAC must fail with wrong signing key")
	}
}
