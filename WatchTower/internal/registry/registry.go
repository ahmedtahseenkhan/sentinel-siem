package registry

import (
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
)

type Registry struct {
	store    *store.Store
	logger   *zap.Logger
	mu       sync.RWMutex
	cmdChans map[string]chan *proto.ManagerCommand
	stopCh   chan struct{}
}

func New(s *store.Store, logger *zap.Logger) *Registry {
	return &Registry{
		store:    s,
		logger:   logger,
		cmdChans: make(map[string]chan *proto.ManagerCommand),
		stopCh:   make(chan struct{}),
	}
}

func (r *Registry) Register(agent *models.Agent) error {
	if agent.RegisteredAt == 0 {
		agent.RegisteredAt = time.Now().UnixMilli()
	}
	agent.LastHeartbeat = time.Now().UnixMilli()
	return r.store.UpsertAgent(agent)
}

func (r *Registry) UpdateHeartbeat(agentID, status string) error {
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

func (r *Registry) checkDisconnected(timeout time.Duration) {
	agents, err := r.store.ListAgents("active", 0, 0)
	if err != nil {
		r.logger.Error("failed to list agents for heartbeat check", zap.Error(err))
		return
	}
	cutoff := time.Now().Add(-timeout).UnixMilli()
	for _, a := range agents {
		if a.LastHeartbeat > 0 && a.LastHeartbeat < cutoff {
			r.logger.Info("agent disconnected", zap.String("agent_id", a.ID), zap.String("hostname", a.Hostname))
			_ = r.store.UpdateAgentHeartbeat(a.ID, string(models.AgentStatusDisconnected))
		}
	}
	agents, err = r.store.ListAgents("streaming", 0, 0)
	if err != nil {
		return
	}
	for _, a := range agents {
		if a.LastHeartbeat > 0 && a.LastHeartbeat < cutoff {
			_ = r.store.UpdateAgentHeartbeat(a.ID, string(models.AgentStatusDisconnected))
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
