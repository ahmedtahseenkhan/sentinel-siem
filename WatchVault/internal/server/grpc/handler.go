package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/watchvault/watchvault/internal/models"
	"github.com/watchvault/watchvault/internal/opensearch"
	"github.com/watchvault/watchvault/internal/pipeline"
	pb "github.com/watchvault/watchvault/pkg/proto"
	"go.uber.org/zap"
)

const (
	maxEventBatchSize  = 5000
	maxAlertBatchSize  = 2000
	maxPayloadBytes    = 1 * 1024 * 1024
	maxEventTypeLen    = 256
	maxIDLen           = 256
	maxTagCount        = 64
	maxTagKeyLen       = 128
	maxTagValueLen     = 4096
	maxRuleGroupsCount = 32
)

// Service implements pb.IndexerServiceServer.
type Service struct {
	pb.UnimplementedIndexerServiceServer
	logger   *zap.Logger
	pipeline *pipeline.Pipeline
	osClient *opensearch.Client
}

func NewService(logger *zap.Logger, p *pipeline.Pipeline, osClient *opensearch.Client) *Service {
	return &Service{
		logger:   logger,
		pipeline: p,
		osClient: osClient,
	}
}

func (s *Service) IngestEvents(stream pb.IndexerService_IngestEventsServer) error {
	var accepted, failed int64
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.IngestResponse{
				Accepted: accepted,
				Failed:   failed,
				Message:  "ok",
			})
		}
		if err != nil {
			return err
		}
		src := batch.GetSourceManager()
		if len(batch.GetEvents()) > maxEventBatchSize {
			s.logger.Warn("event batch exceeds max size", zap.Int("batch_size", len(batch.GetEvents())))
			failed += int64(len(batch.GetEvents()))
			continue
		}
		for _, pe := range batch.GetEvents() {
			if err := validateProtoEvent(pe); err != nil {
				s.logger.Warn("event validation failed", zap.Error(err))
				failed++
				continue
			}
			ev, err := protoIndexEventToModel(pe)
			if err != nil {
				s.logger.Warn("invalid event payload", zap.Error(err))
				failed++
				continue
			}
			if err := s.pipeline.ProcessEvent(ev); err != nil {
				s.logger.Warn("pipeline rejected event", zap.String("id", ev.ID), zap.Error(err))
				failed++
				continue
			}
			accepted++
		}
		s.logger.Debug("event batch ingested",
			zap.String("source", src),
			zap.Int("batch_size", len(batch.GetEvents())),
		)
	}
}

func (s *Service) IngestAlerts(stream pb.IndexerService_IngestAlertsServer) error {
	var accepted, failed int64
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.IngestResponse{
				Accepted: accepted,
				Failed:   failed,
				Message:  "ok",
			})
		}
		if err != nil {
			return err
		}
		if len(batch.GetAlerts()) > maxAlertBatchSize {
			s.logger.Warn("alert batch exceeds max size", zap.Int("batch_size", len(batch.GetAlerts())))
			failed += int64(len(batch.GetAlerts()))
			continue
		}
		for _, pa := range batch.GetAlerts() {
			if err := validateProtoAlert(pa); err != nil {
				s.logger.Warn("alert validation failed", zap.Error(err))
				failed++
				continue
			}
			doc := protoAlertToDoc(pa)
			if err := s.pipeline.ProcessDocument("alerts", doc); err != nil {
				s.logger.Warn("pipeline rejected alert", zap.String("id", pa.GetId()), zap.Error(err))
				failed++
				continue
			}
			accepted++
		}
	}
}

func (s *Service) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	var osStatus int32 = 2
	if s.osClient != nil {
		osStatus = s.osClient.HealthStatus()
	}
	return &pb.HealthResponse{
		Status:            "ok",
		TotalIndexed:      s.pipeline.TotalIndexed(),
		OpensearchStatus:  osStatus,
	}, nil
}

func protoIndexEventToModel(pe *pb.IndexEvent) (*models.IndexEvent, error) {
	ev := &models.IndexEvent{
		ID:        pe.GetId(),
		Timestamp: pe.GetTimestamp(),
		EventType: pe.GetEventType(),
		AgentID:   pe.GetAgentId(),
		AgentName: pe.GetAgentName(),
		Tags:      pe.GetTags(),
		Data:      nil,
	}
	if len(pe.GetData()) > 0 {
		var data map[string]interface{}
		if err := json.Unmarshal(pe.GetData(), &data); err != nil {
			return nil, err
		}
		ev.Data = data
	}
	return ev, nil
}

func protoAlertToDoc(pa *pb.IndexAlert) map[string]interface{} {
	doc := map[string]interface{}{
		"id":               pa.GetId(),
		"timestamp":        pa.GetTimestamp(),
		"rule_id":          int(pa.GetRuleId()),
		"rule_level":       int(pa.GetRuleLevel()),
		"rule_description": pa.GetRuleDescription(),
		"rule_groups":      pa.GetRuleGroups(),
		"agent_id":         pa.GetAgentId(),
		"agent_name":       pa.GetAgentName(),
		"title":            pa.GetTitle(),
	}
	if len(pa.GetEventData()) > 0 {
		var ed map[string]interface{}
		if err := json.Unmarshal(pa.GetEventData(), &ed); err == nil {
			// Flatten all event fields directly to the top level — do NOT store
			// the nested event_data object so OpenSearch Discover shows clean
			// field names instead of event_data.fields.* clutter.
			normalizeAlertFields(doc, ed)
		}
	}
	return doc
}

// normalizeAlertFields flattens event_data.fields to the top level so all
// fields are readable in OpenSearch Discover, then applies semantic aliases
// for common security fields (src_ip, username, etc.).
func normalizeAlertFields(doc map[string]interface{}, ed map[string]interface{}) {
	fields, _ := ed["fields"].(map[string]interface{})
	if fields == nil {
		fields = ed
	}

	// Flatten all raw event fields to the top level so they are visible and
	// searchable in Discover without the event_data.fields.* nesting.
	for k, v := range fields {
		if _, exists := doc[k]; !exists {
			doc[k] = v
		}
	}

	// Event type from nested data (e.g. "network.connection", "process.new")
	if t, _ := ed["type"].(string); t != "" {
		doc["event_category"] = t
	}

	strField := func(key string) string {
		if v, ok := fields[key].(string); ok && v != "" && v != "-" && v != "0.0.0.0" && v != "::" {
			return v
		}
		return ""
	}

	// Semantic aliases — overwrite with normalized names so dashboards and
	// alerts can filter on a consistent field regardless of event source.
	if ip := strField("win_IpAddress"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := strField("src_ip"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := strField("source_ip"); ip != "" {
		doc["src_ip"] = ip
	} else if ip := strField("raddr"); ip != "" {
		doc["src_ip"] = ip
	}

	if ip := strField("dst_ip"); ip != "" {
		doc["dst_ip"] = ip
	} else if ip := strField("dest_ip"); ip != "" {
		doc["dst_ip"] = ip
	} else if ip := strField("laddr"); ip != "" {
		doc["dst_ip"] = ip
	}

	if u := strField("win_TargetUserName"); u != "" {
		doc["username"] = u
	} else if u := strField("user"); u != "" {
		doc["username"] = u
	} else if u := strField("dstuser"); u != "" {
		doc["username"] = u
	}

	if p := strField("name"); p != "" {
		doc["process_name"] = p
	} else if p := strField("process"); p != "" {
		doc["process_name"] = p
	}

	if h := strField("win_WorkstationName"); h != "" {
		doc["src_hostname"] = h
	} else if h := strField("hostname"); h != "" {
		doc["src_hostname"] = h
	}

	if eid, ok := fields["win_event_id"]; ok {
		doc["win_event_id"] = eid
	}
}

func validateProtoEvent(pe *pb.IndexEvent) error {
	if pe == nil {
		return fmt.Errorf("nil event")
	}
	if strings.TrimSpace(pe.GetId()) == "" || len(pe.GetId()) > maxIDLen {
		return fmt.Errorf("invalid event id")
	}
	if strings.TrimSpace(pe.GetEventType()) == "" || len(pe.GetEventType()) > maxEventTypeLen {
		return fmt.Errorf("invalid event type")
	}
	if strings.TrimSpace(pe.GetAgentId()) == "" || len(pe.GetAgentId()) > maxIDLen {
		return fmt.Errorf("invalid agent id")
	}
	if len(pe.GetData()) > maxPayloadBytes {
		return fmt.Errorf("event payload too large")
	}
	if len(pe.GetTags()) > maxTagCount {
		return fmt.Errorf("too many tags")
	}
	for k, v := range pe.GetTags() {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("empty tag key")
		}
		if len(k) > maxTagKeyLen || len(v) > maxTagValueLen {
			return fmt.Errorf("tag key/value too long")
		}
	}
	return nil
}

func validateProtoAlert(pa *pb.IndexAlert) error {
	if pa == nil {
		return fmt.Errorf("nil alert")
	}
	if strings.TrimSpace(pa.GetId()) == "" || len(pa.GetId()) > maxIDLen {
		return fmt.Errorf("invalid alert id")
	}
	if strings.TrimSpace(pa.GetAgentId()) == "" || len(pa.GetAgentId()) > maxIDLen {
		return fmt.Errorf("invalid alert agent id")
	}
	if strings.TrimSpace(pa.GetTitle()) == "" || len(pa.GetTitle()) > maxTagValueLen {
		return fmt.Errorf("invalid alert title")
	}
	if len(pa.GetRuleGroups()) > maxRuleGroupsCount {
		return fmt.Errorf("too many rule groups")
	}
	if len(pa.GetEventData()) > maxPayloadBytes {
		return fmt.Errorf("alert payload too large")
	}
	return nil
}
