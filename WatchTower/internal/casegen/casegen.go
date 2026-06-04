// Package casegen turns high-severity alerts into cases automatically so a
// client with no external ITSM (Jira/ServiceNow) still gets a working ticket
// queue. It attaches to the engine as a CaseHook and runs synchronously on the
// alert hot path, so it returns early for alerts below the configured level.
//
// Repeat alerts for the same (rule + agent) append to the existing open case
// rather than spawning a new one, keeping the queue readable.
package casegen

import (
	"fmt"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// Store is the subset of *store.Store the generator needs. Declared as an
// interface so tests can supply a fake.
type Store interface {
	FindOpenCaseByGroup(groupKey string) (*models.Case, error)
	CreateCase(c *models.Case) (int64, error)
	AppendAlertToCase(caseID, alertID int64) error
	AddCaseNote(note *models.CaseNote) (int64, error)
	AddCaseHistory(h *models.CaseHistory) (int64, error)
}

type Generator struct {
	store  Store
	cfg    config.CasesConfig
	logger *zap.Logger
}

func New(st Store, cfg config.CasesConfig, logger *zap.Logger) *Generator {
	return &Generator{store: st, cfg: cfg, logger: logger}
}

// GroupKey is the (rule + agent) identity used to coalesce repeat alerts into
// one open case. Exported so tests and the store can agree on the format.
func GroupKey(ruleID int, agentID string) string {
	return fmt.Sprintf("rule:%d|agent:%s", ruleID, agentID)
}

// OnAlert implements engine.CaseHook.
func (g *Generator) OnAlert(alert *models.Alert, _ *models.Event) {
	if alert == nil || alert.Level < g.cfg.MinLevelOrDefault() {
		return
	}

	groupKey := GroupKey(alert.RuleID, alert.AgentID)
	existing, err := g.store.FindOpenCaseByGroup(groupKey)
	if err != nil {
		g.logger.Warn("casegen: lookup failed", zap.String("group_key", groupKey), zap.Error(err))
		return
	}

	if existing != nil {
		g.appendToCase(existing, alert)
		return
	}
	g.createCase(groupKey, alert)
}

func (g *Generator) appendToCase(c *models.Case, alert *models.Alert) {
	if err := g.store.AppendAlertToCase(c.ID, alert.ID); err != nil {
		g.logger.Warn("casegen: append alert failed", zap.Int64("case_id", c.ID), zap.Error(err))
		return
	}
	note := &models.CaseNote{
		CaseID:  c.ID,
		Author:  "auto",
		Content: fmt.Sprintf("Recurrence: %s (alert #%d) at %s", alert.Title, alert.ID, fmtTS(alert.Timestamp)),
	}
	if _, err := g.store.AddCaseNote(note); err != nil {
		g.logger.Warn("casegen: add recurrence note failed", zap.Int64("case_id", c.ID), zap.Error(err))
	}
}

func (g *Generator) createCase(groupKey string, alert *models.Alert) {
	priority := PriorityForLevel(alert.Level)
	due := int64(0)
	if d := g.cfg.SLAFor(string(priority)); d > 0 {
		due = time.Now().UnixMilli() + d.Milliseconds()
	}

	agentIDs := []string{}
	if alert.AgentID != "" {
		agentIDs = []string{alert.AgentID}
	}

	c := &models.Case{
		Title:       alert.Title,
		Description: alert.Description,
		Status:      models.CaseStatusOpen,
		Priority:    priority,
		Severity:    alert.Level,
		CreatedBy:   "auto",
		Tags:        []string{"auto-created"},
		AlertIDs:    []int64{alert.ID},
		AgentIDs:    agentIDs,
		GroupKey:    groupKey,
		DueAt:       due,
	}
	id, err := g.store.CreateCase(c)
	if err != nil {
		g.logger.Warn("casegen: create case failed", zap.String("group_key", groupKey), zap.Error(err))
		return
	}
	if _, err := g.store.AddCaseHistory(&models.CaseHistory{
		CaseID:   id,
		Actor:    "auto",
		Action:   "created",
		NewValue: string(models.CaseStatusOpen),
	}); err != nil {
		g.logger.Warn("casegen: add history failed", zap.Int64("case_id", id), zap.Error(err))
	}
	g.logger.Info("casegen: auto-created case",
		zap.Int64("case_id", id),
		zap.Int("rule_id", alert.RuleID),
		zap.String("agent_id", alert.AgentID),
		zap.String("priority", string(priority)))
}

// PriorityForLevel maps a Wazuh-style alert level (0-15) onto a case priority.
func PriorityForLevel(level int) models.CasePriority {
	switch {
	case level >= 12:
		return models.CasePriorityCritical
	case level >= 10:
		return models.CasePriorityHigh
	case level >= 7:
		return models.CasePriorityMedium
	default:
		return models.CasePriorityLow
	}
}

func fmtTS(ms int64) string {
	if ms == 0 {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}
