package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

const (
	TopicEvents = "sentinel.events"
	TopicAlerts = "sentinel.alerts"
)

// kafkaEvent is the wire format for events published to sentinel.events.
// Kept internal — WatchVault decodes the same structure on the consumer side.
type kafkaEvent struct {
	ID        string                 `json:"id"`
	Timestamp int64                  `json:"ts"`
	EventType string                 `json:"event_type"`
	AgentID   string                 `json:"agent_id"`
	AgentName string                 `json:"agent_name,omitempty"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// kafkaAlert is the wire format for alerts published to sentinel.alerts.
type kafkaAlert struct {
	ID          string   `json:"id"`
	RuleID      int      `json:"rule_id"`
	Level       int      `json:"level"`
	AgentID     string   `json:"agent_id"`
	AgentName   string   `json:"agent_name,omitempty"`
	Timestamp   int64    `json:"ts"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	EventData   string   `json:"event_data,omitempty"`
	RuleGroups  []string `json:"rule_groups,omitempty"`
	// Mitre carries the rule's MITRE ATT&CK mapping so WatchVault can index it
	// and the SOC can query by tactic/technique (mitre.technique_id, etc.).
	Mitre []models.MitreMapping `json:"mitre,omitempty"`
}

// KafkaProducer sends events and alerts to Kafka topics.
type KafkaProducer struct {
	client *kgo.Client
	logger *zap.Logger
}

func NewKafkaProducer(brokers []string, logger *zap.Logger) (*KafkaProducer, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ProducerBatchMaxBytes(1<<20),        // 1 MB per batch
		kgo.ProducerLinger(10*time.Millisecond), // micro-batch for throughput
		kgo.RecordRetries(5),
		kgo.RetryTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	return &KafkaProducer{client: client, logger: logger}, nil
}

func (p *KafkaProducer) SendEvents(events []*models.Event) error {
	records := make([]*kgo.Record, 0, len(events))
	for _, e := range events {
		msg := kafkaEvent{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.Type,
			AgentID:   e.AgentID,
			AgentName: e.AgentName,
			Tags:      e.Tags,
			Data:      e.Fields,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			p.logger.Warn("kafka: failed to marshal event", zap.Error(err))
			continue
		}
		records = append(records, &kgo.Record{
			Topic: TopicEvents,
			Key:   []byte(e.AgentID), // partition by agent for ordering
			Value: data,
		})
	}
	return p.client.ProduceSync(context.Background(), records...).FirstErr()
}

func (p *KafkaProducer) SendAlerts(alerts []*models.Alert) error {
	records := make([]*kgo.Record, 0, len(alerts))
	for _, a := range alerts {
		msg := kafkaAlert{
			ID:          fmt.Sprintf("%d", a.ID),
			RuleID:      a.RuleID,
			Level:       a.Level,
			AgentID:     a.AgentID,
			AgentName:   a.AgentName, // hostname (resolved by the engine) — was dropped, leaving the UI to show the hex agent_id
			Timestamp:   a.Timestamp,
			Title:       a.Title,
			Description: a.Description,
			EventData:   a.EventData,
			RuleGroups:  a.RuleGroups,
			Mitre:       a.MitreAttack,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			p.logger.Warn("kafka: failed to marshal alert", zap.Error(err))
			continue
		}
		records = append(records, &kgo.Record{
			Topic: TopicAlerts,
			Key:   []byte(a.AgentID),
			Value: data,
		})
	}
	return p.client.ProduceSync(context.Background(), records...).FirstErr()
}

func (p *KafkaProducer) Close() {
	p.client.Close()
}
