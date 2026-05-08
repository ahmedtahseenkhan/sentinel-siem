package response

import (
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
)

type Manager struct {
	logger   *zap.Logger
	registry *registry.Registry
	store    *store.Store
	actions  map[string]Action
}

func NewManager(logger *zap.Logger, reg *registry.Registry, st *store.Store) *Manager {
	m := &Manager{
		logger:   logger,
		registry: reg,
		store:    st,
		actions:  make(map[string]Action),
	}
	m.registerBuiltinActions()
	return m
}

func (m *Manager) registerBuiltinActions() {
	m.actions["firewall-drop"] = &FirewallDropAction{}
	m.actions["kill-process"] = &KillProcessAction{}
	m.actions["restart-service"] = &RestartServiceAction{}
	m.actions["disable-account"] = &DisableAccountAction{}
}

func (m *Manager) Execute(agentID, action string, params []byte) error {
	cmd := &proto.ManagerCommand{
		CommandType: action,
		Payload:     params,
	}

	sent := m.registry.SendCommand(agentID, cmd)
	if !sent {
		m.logger.Warn("agent not connected for active response",
			zap.String("agent_id", agentID),
			zap.String("action", action),
		)
	}
	return nil
}

func (m *Manager) TriggerFromRule(event *models.Event, rule *models.Rule) {
	if rule.ActiveResponse == nil {
		return
	}

	ar := rule.ActiveResponse
	fieldVal := ""
	if v, ok := event.Fields[ar.Field]; ok {
		fieldVal, _ = v.(string)
	}

	m.logger.Info("active response triggered",
		zap.String("agent_id", event.AgentID),
		zap.String("action", ar.Action),
		zap.String("field", ar.Field),
		zap.String("value", fieldVal),
	)

	_ = m.Execute(event.AgentID, ar.Action, []byte(fieldVal))
}
