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

func (t *Transformer) Transform(event *models.IndexEvent) *models.IndexEvent {
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}

	if event.EventType == "" && event.Data != nil {
		if typ, ok := event.Data["type"].(string); ok {
			event.EventType = typ
		}
	}

	event.EventType = strings.ToLower(event.EventType)
	return event
}
