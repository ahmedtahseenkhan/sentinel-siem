package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/watchvault/watchvault/internal/models"
	"github.com/watchvault/watchvault/internal/pipeline"
	"go.uber.org/zap"
)

const (
	TopicEvents   = "sentinel.events"
	TopicAlerts   = "sentinel.alerts"
	defaultGroup  = "sentinel-watchvault"
)

// kafkaEvent mirrors the wire format produced by WatchTower's kafka_producer.go.
type kafkaEvent struct {
	ID        string                 `json:"id"`
	Timestamp int64                  `json:"ts"`
	EventType string                 `json:"event_type"`
	AgentID   string                 `json:"agent_id"`
	AgentName string                 `json:"agent_name,omitempty"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// kafkaAlert mirrors the wire format produced by WatchTower's kafka_producer.go.
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
}

// Consumer reads events and alerts from Kafka and feeds them into the pipeline.
type Consumer struct {
	client   *kgo.Client
	pipeline *pipeline.Pipeline
	logger   *zap.Logger
}

func New(brokers []string, group string, p *pipeline.Pipeline, logger *zap.Logger) (*Consumer, error) {
	if group == "" {
		group = defaultGroup
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(TopicEvents, TopicAlerts),
		kgo.FetchMaxWait(500*time.Millisecond),
		kgo.FetchMaxBytes(10<<20), // 10 MB per fetch
	)
	if err != nil {
		return nil, fmt.Errorf("create kafka consumer: %w", err)
	}
	return &Consumer{client: client, pipeline: p, logger: logger}, nil
}

// Start runs the consume loop in the background until ctx is cancelled.
func (c *Consumer) Start(ctx context.Context) {
	go c.loop(ctx)
	c.logger.Info("kafka consumer started",
		zap.Strings("topics", []string{TopicEvents, TopicAlerts}))
}

func (c *Consumer) loop(ctx context.Context) {
	for {
		fetches := c.client.PollFetches(ctx)
		if ctx.Err() != nil || fetches.IsClientClosed() {
			c.client.Close()
			return
		}
		fetches.EachError(func(t string, p int32, err error) {
			c.logger.Error("kafka fetch error",
				zap.String("topic", t), zap.Int32("partition", p), zap.Error(err))
		})
		fetches.EachRecord(func(r *kgo.Record) {
			switch r.Topic {
			case TopicEvents:
				c.handleEvent(r.Value)
			case TopicAlerts:
				c.handleAlert(r.Value)
			}
		})
	}
}

func (c *Consumer) handleEvent(data []byte) {
	var e kafkaEvent
	if err := json.Unmarshal(data, &e); err != nil {
		c.logger.Warn("kafka: failed to decode event", zap.Error(err))
		return
	}
	// Flatten Kafka event fields — WatchTower sends events with all fields
	// nested under e.Data (e.g. {"raddr":"1.2.3.4","win_IpAddress":"..."}).
	// Merge them into a flat Data map so pipeline.eventToDoc can normalize them.
	ev := &models.IndexEvent{
		ID:        e.ID,
		Timestamp: e.Timestamp,
		EventType: e.EventType,
		AgentID:   e.AgentID,
		AgentName: e.AgentName,
		Tags:      e.Tags,
		Data:      e.Data,
	}
	if err := c.pipeline.ProcessEvent(ev); err != nil {
		c.logger.Warn("kafka: pipeline rejected event", zap.String("id", e.ID), zap.Error(err))
	}
}

func (c *Consumer) handleAlert(data []byte) {
	var a kafkaAlert
	if err := json.Unmarshal(data, &a); err != nil {
		c.logger.Warn("kafka: failed to decode alert", zap.Error(err))
		return
	}
	doc := map[string]interface{}{
		"id":               a.ID,
		"rule_id":          a.RuleID,
		"rule_level":       a.Level,
		"rule_description": a.Description,
		"rule_groups":      a.RuleGroups,
		"agent_id":         a.AgentID,
		"agent_name":       a.AgentName,
		"title":            a.Title,
		"timestamp":        a.Timestamp,
	}
	if a.EventData != "" {
		var ed map[string]interface{}
		if err := json.Unmarshal([]byte(a.EventData), &ed); err == nil {
			doc["event_data"] = ed
			normalizeAlertFields(doc, ed)
		} else {
			doc["event_data"] = a.EventData
		}
	}
	if err := c.pipeline.ProcessDocument("alerts", doc); err != nil {
		c.logger.Warn("kafka: pipeline rejected alert", zap.String("id", a.ID), zap.Error(err))
	}
}

// normalizeAlertFields extracts IPs, usernames, and process names from
// event_data.fields to top-level fields so OpenSearch can search and
// aggregate them in Discover and dashboards.
func normalizeAlertFields(doc map[string]interface{}, ed map[string]interface{}) {
	fields, _ := ed["fields"].(map[string]interface{})
	if fields == nil {
		fields = ed
	}

	str := func(key string) string {
		if v, ok := fields[key].(string); ok && v != "" && v != "-" && v != "0.0.0.0" && v != "::" {
			return v
		}
		return ""
	}

	// Source IP
	if ip := str("win_IpAddress"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := str("src_ip"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := str("source_ip"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := str("raddr"); ip != "" {
		doc["src_ip"] = ip
	}

	// Destination IP
	if ip := str("dst_ip"); ip != "" {
		doc["dst_ip"] = ip
	} else if ip := str("laddr"); ip != "" {
		doc["dst_ip"] = ip
	}

	// Username
	if u := str("win_TargetUserName"); u != "" {
		doc["username"] = u
	} else if u := str("user"); u != "" {
		doc["username"] = u
	} else if u := str("dstuser"); u != "" {
		doc["username"] = u
	}

	// Process name
	if p := str("name"); p != "" {
		doc["process_name"] = p
	} else if p := str("process"); p != "" {
		doc["process_name"] = p
	}

	// Hostname
	if h := str("win_WorkstationName"); h != "" {
		doc["src_hostname"] = h
	} else if h := str("hostname"); h != "" {
		doc["src_hostname"] = h
	}

	// Windows Event ID
	if eid, ok := fields["win_event_id"]; ok {
		doc["win_event_id"] = eid
	}

	// Event category
	if t, _ := ed["type"].(string); t != "" {
		doc["event_category"] = t
	}
}
