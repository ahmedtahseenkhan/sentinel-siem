package registry

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
)

// EventSink receives agent lifecycle events so the rules engine can fire
// alert rules 501-509 (connect/disconnect/reconnect) just like Wazuh does.
type EventSink interface {
	Ingest(event *models.Event)
}

type Registry struct {
	store          *store.Store
	logger         *zap.Logger
	mu             sync.RWMutex
	cmdChans       map[string]chan *proto.ManagerCommand
	stopCh         chan struct{}
	disconnectHook func(agent *models.Agent)
	engine         EventSink
}

func New(s *store.Store, logger *zap.Logger) *Registry {
	return &Registry{
		store:    s,
		logger:   logger,
		cmdChans: make(map[string]chan *proto.ManagerCommand),
		stopCh:   make(chan struct{}),
	}
}

// SetDisconnectHook registers an optional callback invoked for each agent
// that transitions to disconnected during a heartbeat sweep.
func (r *Registry) SetDisconnectHook(fn func(*models.Agent)) {
	r.disconnectHook = fn
}

// SetEngine wires the rules engine so agent lifecycle events (connect /
// disconnect / reconnect) are ingested and can trigger alert rules 501-509.
func (r *Registry) SetEngine(e EventSink) {
	r.mu.Lock()
	r.engine = e
	r.mu.Unlock()
}

func (r *Registry) Register(a *models.Agent) error {
	isNew := a.RegisteredAt == 0
	if isNew {
		a.RegisteredAt = time.Now().UnixMilli()
	}
	a.LastHeartbeat = time.Now().UnixMilli()
	if err := r.store.UpsertAgent(a); err != nil {
		return err
	}
	if isNew {
		r.ingestLifecycleEvent("agent.enrolled", a)
	} else {
		r.ingestLifecycleEvent("agent.reconnected", a)
	}
	return nil
}

func (r *Registry) UpdateHeartbeat(agentID, status string) error {
	if status == "connected" {
		if a, err := r.store.GetAgent(agentID); err == nil {
			r.ingestLifecycleEvent("agent.connected", a)
		}
	}
	return r.store.UpdateAgentHeartbeat(agentID, status)
}

func (r *Registry) GetAgent(id string) (*models.Agent, error) {
	return r.store.GetAgent(id)
}

func (r *Registry) ListAgents(status string, limit, offset int) ([]*models.Agent, error) {
	return r.store.ListAgents(status, limit, offset)
}

func (r *Registry) DeleteAgent(id string) error {
	r.mu.Lock()
	if ch, ok := r.cmdChans[id]; ok {
		close(ch)
		delete(r.cmdChans, id)
	}
	r.mu.Unlock()
	return r.store.DeleteAgent(id)
}

func (r *Registry) GetCommandChannel(agentID string) <-chan *proto.ManagerCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.cmdChans[agentID]
	if !ok {
		ch = make(chan *proto.ManagerCommand, 64)
		r.cmdChans[agentID] = ch
	}
	return ch
}

func (r *Registry) SendCommand(agentID string, cmd *proto.ManagerCommand) bool {
	r.mu.RLock()
	ch, ok := r.cmdChans[agentID]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case ch <- cmd:
		return true
	default:
		r.logger.Warn("command channel full, dropping command",
			zap.String("agent_id", agentID),
			zap.String("command_id", cmd.CommandId),
		)
		return false
	}
}

func (r *Registry) StartHeartbeatMonitor(interval time.Duration, timeout time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				r.checkDisconnected(timeout)
			}
		}
	}()
}

// checkDisconnected runs a single UPDATE query — O(1) regardless of agent count.
// Any agents that just transitioned to disconnected are logged and passed to
// the optional disconnectHook.
func (r *Registry) checkDisconnected(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout).UnixMilli()
	agents, err := r.store.MarkDisconnectedBefore(cutoff)
	if err != nil {
		r.logger.Error("heartbeat check failed", zap.Error(err))
		return
	}
	for _, a := range agents {
		r.logger.Warn("agent disconnected",
			zap.String("agent_id", a.ID),
			zap.String("hostname", a.Hostname),
			zap.Int64("last_heartbeat", a.LastHeartbeat),
		)
		r.ingestLifecycleEvent("agent.disconnected", a)
		if r.disconnectHook != nil {
			r.disconnectHook(a)
		}
	}
}

func (r *Registry) Stop() {
	close(r.stopCh)
}

func (r *Registry) CountAgents() (total, active, disconnected int, err error) {
	return r.store.CountAgents()
}

func (r *Registry) UpdateAgentGroup(agentID, groupID string) error {
	return r.store.UpdateAgentGroup(agentID, groupID)
}

// ingestLifecycleEvent sends an agent lifecycle event into the rules engine
// so rules 501-509 (agent.enrolled, agent.connected, agent.disconnected, etc.)
// can fire alerts — identical to how Wazuh rules 502/504/508 work.
func (r *Registry) ingestLifecycleEvent(eventType string, a *models.Agent) {
	r.mu.RLock()
	eng := r.engine
	r.mu.RUnlock()
	if eng == nil {
		return
	}
	eng.Ingest(&models.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UnixMilli(),
		Type:      eventType,
		AgentID:   a.ID,
		AgentName: a.Hostname,
		Fields: map[string]interface{}{
			"hostname":       a.Hostname,
			"agent_id":       a.ID,
			"os":             a.OS,
			"platform":       a.Platform,
			"version":        a.Version,
			"last_heartbeat": a.LastHeartbeat,
			"status":         a.Status,
		},
		Tags: map[string]string{
			"source":     "agent_lifecycle",
			"event_type": eventType,
		},
	})
}
