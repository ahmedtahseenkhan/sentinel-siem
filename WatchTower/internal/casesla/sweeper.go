// Package casesla runs a background sweeper that enforces case SLAs: it finds
// open cases past their due date, flags them as breached, escalates their
// priority one level, records the change in the audit trail, and fires an
// outbound notification (reusing the same Slack/Teams/email notifier as alerts).
package casesla

import (
	"context"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// Store is the subset of *store.Store the sweeper needs.
type Store interface {
	ListOverdueCases(now int64) ([]*models.Case, error)
	MarkCaseBreached(id int64, newPriority string) error
	AddCaseHistory(h *models.CaseHistory) (int64, error)
	ListWarnableCases(now int64) ([]*models.Case, error)
	MarkCaseWarned(id int64) error
	SetCaseAssignee(id int64, assignee string) error
}

// Notifier dispatches SLA notifications. *notifier.Notifier satisfies it.
type Notifier interface {
	OnCaseBreach(c *models.Case)
	OnCaseWarning(c *models.Case)
}

// Assigner reassigns a breached case to a more senior tier (the case's priority
// is already escalated when this is called). *assign.Engine satisfies it.
type Assigner interface {
	Route(c *models.Case) (assignee, reason string)
}

type Sweeper struct {
	store    Store
	notifier Notifier // may be nil when notifications are disabled
	assigner Assigner // may be nil when assignment is disabled
	cfg      config.CasesConfig
	logger   *zap.Logger
}

func New(st Store, n Notifier, cfg config.CasesConfig, logger *zap.Logger) *Sweeper {
	return &Sweeper{store: st, notifier: n, cfg: cfg, logger: logger}
}

// SetAssigner wires the assignment engine for breach tier-escalation (optional).
func (s *Sweeper) SetAssigner(a Assigner) { s.assigner = a }

// Start runs the sweep loop until ctx is cancelled. Call with `go`.
func (s *Sweeper) Start(ctx context.Context) {
	interval := s.cfg.SweepInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.logger.Info("case SLA sweeper started", zap.Duration("interval", interval))
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("case SLA sweeper stopped")
			return
		case <-ticker.C:
			s.Sweep()
		}
	}
}

// Sweep performs one pass. Exported so tests can drive it deterministically.
func (s *Sweeper) Sweep() {
	now := time.Now().UnixMilli()

	// 1) Warning pass — cases approaching their SLA (~80%) that haven't breached.
	warns, err := s.store.ListWarnableCases(now)
	if err != nil {
		s.logger.Warn("case SLA sweep: list warnable failed", zap.Error(err))
	}
	for _, c := range warns {
		if err := s.store.MarkCaseWarned(c.ID); err != nil {
			s.logger.Warn("case SLA sweep: mark warned failed", zap.Int64("case_id", c.ID), zap.Error(err))
			continue
		}
		_, _ = s.store.AddCaseHistory(&models.CaseHistory{
			CaseID: c.ID, Actor: "sla", Action: "sla_warning", Field: "warn_at",
		})
		c.Warned = true
		if s.notifier != nil {
			s.notifier.OnCaseWarning(c)
		}
	}
	if len(warns) > 0 {
		s.logger.Info("case SLA sweep: warnings sent", zap.Int("count", len(warns)))
	}

	// 2) Breach pass.
	cases, err := s.store.ListOverdueCases(now)
	if err != nil {
		s.logger.Warn("case SLA sweep: list overdue failed", zap.Error(err))
		return
	}
	for _, c := range cases {
		newPriority := EscalatePriority(c.Priority)
		changed := ""
		if newPriority != c.Priority {
			changed = string(newPriority)
		}
		if err := s.store.MarkCaseBreached(c.ID, changed); err != nil {
			s.logger.Warn("case SLA sweep: mark breached failed", zap.Int64("case_id", c.ID), zap.Error(err))
			continue
		}
		if _, err := s.store.AddCaseHistory(&models.CaseHistory{
			CaseID:   c.ID,
			Actor:    "sla",
			Action:   "sla_breached",
			Field:    "priority",
			OldValue: string(c.Priority),
			NewValue: string(newPriority),
		}); err != nil {
			s.logger.Warn("case SLA sweep: add history failed", zap.Int64("case_id", c.ID), zap.Error(err))
		}
		// Reflect the new state on the in-memory copy for the notification.
		c.Priority = newPriority
		c.SLABreached = true
		c.Escalated = true

		// Escalate ownership: re-route to a more senior tier (Route picks tier
		// from the now-escalated priority). Skip if it lands on the same person.
		if s.assigner != nil {
			if assignee, reason := s.assigner.Route(c); assignee != "" && assignee != c.Assignee {
				if err := s.store.SetCaseAssignee(c.ID, assignee); err == nil {
					_, _ = s.store.AddCaseHistory(&models.CaseHistory{
						CaseID: c.ID, Actor: "sla", Action: "escalated", Field: "assignee",
						OldValue: c.Assignee, NewValue: assignee,
					})
					s.logger.Info("case SLA sweep: escalated owner",
						zap.Int64("case_id", c.ID), zap.String("assignee", assignee), zap.String("reason", reason))
					c.Assignee = assignee
				}
			}
		}

		if s.notifier != nil {
			s.notifier.OnCaseBreach(c)
		}
	}
	if len(cases) > 0 {
		s.logger.Info("case SLA sweep: cases breached", zap.Int("count", len(cases)))
	}
}

// EscalatePriority bumps a priority one level toward critical (critical stays).
func EscalatePriority(p models.CasePriority) models.CasePriority {
	switch p {
	case models.CasePriorityLow:
		return models.CasePriorityMedium
	case models.CasePriorityMedium:
		return models.CasePriorityHigh
	case models.CasePriorityHigh:
		return models.CasePriorityCritical
	default:
		return models.CasePriorityCritical
	}
}
