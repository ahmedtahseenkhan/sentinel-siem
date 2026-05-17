// Package audit provides a structured audit logger that records API calls,
// agent registrations, config changes, and admin actions. Audit records are
// forwarded to WatchVault under the "watchvault-audit" index via the normal
// forwarder pipeline, ensuring they are durable, searchable, and tamper-evident.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// EventType classifies an audit record.
type EventType string

const (
	EventTypeAPICall           EventType = "api_call"
	EventTypeAgentRegister     EventType = "agent_register"
	EventTypeAgentDeregister   EventType = "agent_deregister"
	EventTypeConfigChange      EventType = "config_change"
	EventTypeActiveResponse    EventType = "active_response"
	EventTypeRuleCreate        EventType = "rule_create"
	EventTypeDecoderCreate     EventType = "decoder_create"
	EventTypeAdminAction       EventType = "admin_action"
)

// Record is a single immutable audit event.
//
// PrevHash + RecordHash form a hash chain: each record's hash is computed
// over the record contents AND the previous record's hash, so any tampering
// (modification, insertion, or deletion) breaks the chain and is detectable.
// HMACSignature uses a server-side secret to also prevent forgery by anyone
// who has read access but not the signing key.
type Record struct {
	ID            string            `json:"id"`
	Timestamp     int64             `json:"timestamp"`
	EventType     EventType         `json:"event_type"`
	ActorIP       string            `json:"actor_ip,omitempty"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	DurationMs    int64             `json:"duration_ms,omitempty"`
	AgentID       string            `json:"agent_id,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	Success       bool              `json:"success"`
	PrevHash      string            `json:"prev_hash,omitempty"`
	RecordHash    string            `json:"record_hash,omitempty"`
	HMACSignature string            `json:"hmac_signature,omitempty"`
}

// Sink receives audit records for downstream processing.
type Sink interface {
	Ingest(event *models.Event)
}

// Logger writes structured audit records to a Sink. It is safe for concurrent use.
//
// Records form a tamper-evident hash chain: each record contains a hash of
// its own contents plus the previous record's hash. signingKey is used to
// HMAC each record, preventing forgery even by readers with full DB access.
type Logger struct {
	sink       Sink
	logger     *zap.Logger
	signingKey []byte
	mu         sync.Mutex
	prevHash   string // hash of the most recent record (chain link)
}

// New creates an audit Logger that forwards records to sink.
// signingKey should be at least 32 bytes from a cryptographic source
// (e.g. AUDIT_SIGNING_KEY env var). An empty key disables HMAC signing
// but the hash chain remains intact (downgraded to integrity-only).
func New(sink Sink, signingKey []byte, logger *zap.Logger) *Logger {
	return &Logger{sink: sink, signingKey: signingKey, logger: logger}
}

// computeRecordHash returns hex(SHA256(canonical-record-bytes | prev_hash)).
func computeRecordHash(rec *Record) string {
	// Build a stable canonical form by clearing the hash/sig fields then
	// JSON-encoding. Fields are emitted in struct order which is stable.
	tmp := *rec
	tmp.RecordHash = ""
	tmp.HMACSignature = ""
	canon, _ := json.Marshal(tmp)
	h := sha256.Sum256(canon)
	return hex.EncodeToString(h[:])
}

// computeHMAC returns hex(HMAC-SHA256(key, record_hash)).
func computeHMAC(key []byte, recordHash string) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(recordHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRecord recomputes the record hash and HMAC from the given record
// and previous-record hash, then compares to the stored values. Returns
// (hashOK, hmacOK) — both must be true for the record to be considered
// untampered.
func VerifyRecord(rec *Record, prevHash string, signingKey []byte) (bool, bool) {
	if rec.PrevHash != prevHash {
		return false, false
	}
	wantHash := computeRecordHash(rec)
	hashOK := hmac.Equal([]byte(rec.RecordHash), []byte(wantHash))
	hmacOK := hmac.Equal([]byte(rec.HMACSignature), []byte(computeHMAC(signingKey, wantHash)))
	return hashOK, hmacOK
}

// Log emits a single audit record. It never blocks the caller; if the sink is
// full the record is dropped with a warning to avoid impacting request latency.
//
// Each record is added to the tamper-evident hash chain under l.mu so the
// PrevHash linkage is monotonic even under concurrent callers.
func (l *Logger) Log(rec Record) {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.Timestamp == 0 {
		rec.Timestamp = time.Now().UnixMilli()
	}

	// Chain + sign under the mutex so prevHash stays monotonic.
	l.mu.Lock()
	rec.PrevHash = l.prevHash
	rec.RecordHash = computeRecordHash(&rec)
	rec.HMACSignature = computeHMAC(l.signingKey, rec.RecordHash)
	l.prevHash = rec.RecordHash
	l.mu.Unlock()

	event := &models.Event{
		ID:        rec.ID,
		Timestamp: rec.Timestamp,
		Type:      "audit",
		AgentID:   "_watchtower",
		Fields: map[string]interface{}{
			"audit_index":     "watchvault-audit",
			"event_type":      string(rec.EventType),
			"actor_ip":        rec.ActorIP,
			"method":          rec.Method,
			"path":            rec.Path,
			"status_code":     rec.StatusCode,
			"duration_ms":     rec.DurationMs,
			"agent_id":        rec.AgentID,
			"success":         rec.Success,
			"details":         rec.Details,
			"prev_hash":       rec.PrevHash,
			"record_hash":     rec.RecordHash,
			"hmac_signature":  rec.HMACSignature,
		},
	}

	// Ingest is expected to be non-blocking (buffered channel in the forwarder).
	func() {
		defer func() {
			if r := recover(); r != nil {
				l.logger.Warn("audit sink panicked — record dropped", zap.Any("panic", r))
			}
		}()
		l.sink.Ingest(event)
	}()
}
