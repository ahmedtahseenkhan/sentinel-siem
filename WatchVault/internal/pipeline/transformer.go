package pipeline

import (
	"strings"
	"time"

	"github.com/watchvault/watchvault/internal/models"
)

type Transformer struct{}

func NewTransformer() *Transformer {
	return &Transformer{}
}

// nanosecondThreshold is the smallest value that is unambiguously nanoseconds
// (year 2001 in ms = 1e12, year 2001 in ns = 1e18 — safe cutoff at 1e15).
const nanosecondThreshold = int64(1e15)

func (t *Transformer) Transform(event *models.IndexEvent) *models.IndexEvent {
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	} else if event.Timestamp > nanosecondThreshold {
		// Convert nanoseconds → milliseconds
		event.Timestamp = event.Timestamp / 1_000_000
	}

	if event.EventType == "" && event.Data != nil {
		if typ, ok := event.Data["type"].(string); ok {
			event.EventType = typ
		}
	}

	event.EventType = strings.ToLower(event.EventType)
	return event
}
