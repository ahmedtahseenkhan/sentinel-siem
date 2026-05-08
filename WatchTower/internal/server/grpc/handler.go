package grpc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/audit"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
)

const (
	maxBatchPoints      = 5000
	maxFieldCount       = 256
	maxTagCount         = 64
	maxKeyLen           = 128
	maxStringValueLen   = 4096
	maxBytesValueLen    = 64 * 1024
	maxIdentityFieldLen = 256
)

// EventSink receives decoded events from the gRPC handler for processing by the engine.
type EventSink interface {
	Ingest(event *models.Event)
}

// AgentRegistry manages agent lifecycle.
type AgentRegistry interface {
	Register(agent *models.Agent) error
	UpdateHeartbeat(agentID, status string) error
	GetCommandChannel(agentID string) <-chan *proto.ManagerCommand
}

type Handler struct {
	proto.UnimplementedAgentServiceServer
	logger      *zap.Logger
	registry    AgentRegistry
	sink        EventSink
	enrollToken []byte // nil means enrollment auth is disabled
	audit       *audit.Logger
}

// NewHandler creates a gRPC handler. When enrollToken is non-empty every
// Register() call must supply a matching "_enroll_token" label; the token is
// stripped from stored agent labels before registration completes.
func NewHandler(logger *zap.Logger, registry AgentRegistry, sink EventSink, enrollToken string) *Handler {
	var tok []byte
	if enrollToken != "" {
		tok = []byte(enrollToken)
	}
	return &Handler{logger: logger, registry: registry, sink: sink, enrollToken: tok}
}

// SetAuditLogger attaches an audit.Logger that records registration events.
func (h *Handler) SetAuditLogger(al *audit.Logger) {
	h.audit = al
}

func (h *Handler) Register(ctx context.Context, req *proto.RegistrationRequest) (*proto.RegistrationResponse, error) {
	if req.AgentId == "" {
		return &proto.RegistrationResponse{Accepted: false, Message: "missing agent_id"}, nil
	}
	if err := validateRegistration(req); err != nil {
		return &proto.RegistrationResponse{Accepted: false, Message: err.Error()}, nil
	}

	// Enrollment token check — constant-time comparison to prevent timing attacks.
	if len(h.enrollToken) > 0 {
		provided := []byte(req.Labels["_enroll_token"])
		if subtle.ConstantTimeCompare(provided, h.enrollToken) != 1 {
			h.logger.Warn("agent registration rejected: invalid enroll token",
				zap.String("agent_id", req.AgentId),
			)
			return &proto.RegistrationResponse{Accepted: false, Message: "invalid enrollment token"}, nil
		}
		// Strip the token so it is never persisted in the registry.
		clean := make(map[string]string, len(req.Labels))
		for k, v := range req.Labels {
			if k != "_enroll_token" {
				clean[k] = v
			}
		}
		req.Labels = clean
	}

	agent := &models.Agent{
		ID:           req.AgentId,
		Hostname:     req.Hostname,
		OS:           req.Os,
		Platform:     req.Platform,
		Version:      req.Version,
		Labels:       req.Labels,
		Status:       models.AgentStatusActive,
		RegisteredAt: time.Now().UnixMilli(),
	}

	if err := h.registry.Register(agent); err != nil {
		h.logger.Error("agent registration failed", zap.String("agent_id", req.AgentId), zap.Error(err))
		if h.audit != nil {
			h.audit.Log(audit.Record{
				EventType: audit.EventTypeAgentRegister,
				AgentID:   req.AgentId,
				Success:   false,
				Details:   map[string]string{"error": err.Error(), "hostname": req.Hostname},
			})
		}
		return &proto.RegistrationResponse{Accepted: false, Message: err.Error()}, nil
	}

	if h.audit != nil {
		h.audit.Log(audit.Record{
			EventType: audit.EventTypeAgentRegister,
			AgentID:   req.AgentId,
			Success:   true,
			Details:   map[string]string{"hostname": req.Hostname, "platform": req.Platform, "version": req.Version},
		})
	}
	h.logger.Info("agent registered",
		zap.String("agent_id", req.AgentId),
		zap.String("hostname", req.Hostname),
		zap.String("platform", req.Platform),
	)
	return &proto.RegistrationResponse{Accepted: true, Message: "ok", AgentId: req.AgentId}, nil
}

func (h *Handler) Heartbeat(ctx context.Context, req *proto.HeartbeatRequest) (*proto.HeartbeatResponse, error) {
	if req.AgentId == "" {
		return &proto.HeartbeatResponse{Acknowledged: false, ServerTime: time.Now().UnixNano()}, nil
	}
	if err := h.registry.UpdateHeartbeat(req.AgentId, req.Status); err != nil {
		h.logger.Warn("heartbeat update failed", zap.String("agent_id", req.AgentId), zap.Error(err))
	}
	return &proto.HeartbeatResponse{Acknowledged: true, ServerTime: time.Now().UnixNano()}, nil
}

func (h *Handler) StreamData(stream proto.AgentService_StreamDataServer) error {
	ctx := stream.Context()
	var agentID string
	var cmdCh <-chan *proto.ManagerCommand

	sendDone := make(chan struct{})
	defer close(sendDone)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch, err := stream.Recv()
		if err != nil {
			return err
		}

		if agentID == "" {
			agentID = batch.AgentId
			if agentID == "" {
				return fmt.Errorf("missing agent_id in first batch")
			}
			// When mTLS is active, enforce that the cert CN matches the claimed
			// agent_id so a rogue agent cannot impersonate another.
			if cn := PeerCN(ctx); cn != "" && cn != agentID {
				h.logger.Warn("agent_id mismatch with cert CN — rejecting stream",
					zap.String("agent_id", agentID),
					zap.String("cert_cn", cn),
				)
				return fmt.Errorf("agent_id %q does not match certificate CN %q", agentID, cn)
			}
			_ = h.registry.UpdateHeartbeat(agentID, "streaming")

			if h.registry != nil {
				cmdCh = h.registry.GetCommandChannel(agentID)
			}
			if cmdCh != nil {
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						case <-sendDone:
							return
						case cmd, ok := <-cmdCh:
							if !ok || cmd == nil {
								return
							}
							_ = stream.Send(cmd)
						}
					}
				}()
			}
		}

		if batch.AgentId != agentID {
			return fmt.Errorf("agent_id changed within stream")
		}
		if len(batch.Points) > maxBatchPoints {
			return fmt.Errorf("batch exceeds max points: %d", len(batch.Points))
		}

		_ = h.registry.UpdateHeartbeat(agentID, "streaming")

		for _, pt := range batch.Points {
			if err := validateDataPoint(pt); err != nil {
				h.logger.Warn("invalid data point dropped", zap.String("agent_id", agentID), zap.Error(err))
				continue
			}
			event := convertDataPoint(agentID, pt)
			if h.sink != nil {
				h.sink.Ingest(event)
			}
		}

		h.logger.Debug("batch processed",
			zap.String("agent_id", agentID),
			zap.Int("points", len(batch.Points)),
		)
	}
}

func validateRegistration(req *proto.RegistrationRequest) error {
	if len(req.AgentId) > maxIdentityFieldLen {
		return fmt.Errorf("agent_id too long")
	}
	if len(req.Hostname) > maxIdentityFieldLen {
		return fmt.Errorf("hostname too long")
	}
	if len(req.Os) > maxIdentityFieldLen {
		return fmt.Errorf("os too long")
	}
	if len(req.Platform) > maxIdentityFieldLen {
		return fmt.Errorf("platform too long")
	}
	if len(req.Version) > maxIdentityFieldLen {
		return fmt.Errorf("version too long")
	}
	if len(req.Labels) > maxTagCount {
		return fmt.Errorf("too many labels")
	}
	for k, v := range req.Labels {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("label key is empty")
		}
		if len(k) > maxKeyLen || len(v) > maxStringValueLen {
			return fmt.Errorf("label key/value too long")
		}
	}
	return nil
}

func validateDataPoint(pt *proto.DataPoint) error {
	if pt == nil {
		return fmt.Errorf("nil data point")
	}
	if strings.TrimSpace(pt.Type) == "" {
		return fmt.Errorf("missing event type")
	}
	if len(pt.Type) > maxIdentityFieldLen {
		return fmt.Errorf("event type too long")
	}
	if len(pt.Fields) > maxFieldCount {
		return fmt.Errorf("too many fields")
	}
	if len(pt.Tags) > maxTagCount {
		return fmt.Errorf("too many tags")
	}

	for k, v := range pt.Fields {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("field key is empty")
		}
		if len(k) > maxKeyLen {
			return fmt.Errorf("field key too long")
		}
		if v == nil {
			continue
		}
		switch val := v.Value.(type) {
		case *proto.Value_StringValue:
			if len(val.StringValue) > maxStringValueLen {
				return fmt.Errorf("string field value too long")
			}
		case *proto.Value_BytesValue:
			if len(val.BytesValue) > maxBytesValueLen {
				return fmt.Errorf("bytes field value too large")
			}
		}
	}

	for k, v := range pt.Tags {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("tag key is empty")
		}
		if len(k) > maxKeyLen || len(v) > maxStringValueLen {
			return fmt.Errorf("tag key/value too long")
		}
	}

	return nil
}

func convertDataPoint(agentID string, pt *proto.DataPoint) *models.Event {
	fields := make(map[string]interface{}, len(pt.Fields))
	for k, v := range pt.Fields {
		switch val := v.Value.(type) {
		case *proto.Value_StringValue:
			fields[k] = val.StringValue
		case *proto.Value_IntValue:
			fields[k] = val.IntValue
		case *proto.Value_DoubleValue:
			fields[k] = val.DoubleValue
		case *proto.Value_BoolValue:
			fields[k] = val.BoolValue
		case *proto.Value_BytesValue:
			fields[k] = val.BytesValue
		}
	}

	return &models.Event{
		Timestamp: pt.Timestamp,
		Type:      pt.Type,
		AgentID:   agentID,
		Fields:    fields,
		Tags:      pt.Tags,
	}
}
