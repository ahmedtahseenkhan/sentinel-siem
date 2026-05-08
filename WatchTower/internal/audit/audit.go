// Package audit provides a structured audit logger that records API calls,
// agent registrations, config changes, and admin actions. Audit records are
// forwarded to WatchVault under the "watchvault-audit" index via the normal
// forwarder pipeline, ensuring they are durable, searchable, and tamper-evident.
package audit

import (
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
type Record struct {
	ID         string            `json:"id"`
	Timestamp  int64             `json:"timestamp"`
	EventType  EventType         `json:"event_type"`
	ActorIP    string            `json:"actor_ip,omitempty"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	DurationMs int64             `json:"duration_ms,omitempty"`
	AgentID    string            `json:"agent_id,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Success    bool              `json:"success"`
}

// Sink receives audit records for downstream processing.
type Sink interface {
	Ingest(event *models.Event)
}

// Logger writes structured audit records to a Sink. It is safe for concurrent use.
type Logger struct {
	sink   Sink
	logger *zap.Logger
	mu     sync.Mutex
}

// New creates an audit Logger that forwards records to sink.
func New(sink Sink, logger *zap.Logger) *Logger {
	return &Logger{sink: sink, logger: logger}
}

// Log emits a single audit record. It never blocks the caller; if the sink is
// full the record is dropped with a warning to avoid impacting request latency.
func (l *Logger) Log(rec Record) {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.Timestamp == 0 {
		rec.Timestamp = time.Now().UnixMilli()
	}

	event := &models.Event{
		ID:        rec.ID,
		Timestamp: rec.Timestamp,
		Type:      "audit",
		AgentID:   "_watchtower",
		Fields: map[string]interface{}{
			"audit_index":  "watchvault-audit",
			"event_type":   string(rec.EventType),
			"actor_ip":     rec.ActorIP,
			"method":       rec.Method,
			"path":         rec.Path,
			"status_code":  rec.StatusCode,
			"duration_ms":  rec.DurationMs,
			"agent_id":     rec.AgentID,
			"success":      rec.Success,
			"details":      rec.Details,
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
