// Package rba implements Risk-Based Alerting for Sentinel SIEM.
//
// Instead of alerting on every event, RBA accumulates risk points per entity
// across multiple alerts and fires a "Risk Notable" only when accumulated risk
// exceeds a configured threshold. This reduces low-fidelity alert fatigue by
// ~90% while surfacing high-fidelity, context-rich incidents.
//
// Risk lifecycle:
//  1. Alert fires → rule risk weight looked up (or derived from level)
//  2. Risk event created with expires_at = now + decay_hours
//  3. Entity risk = SUM(unexpired risk events)
//  4. If score > threshold AND cooldown elapsed → Risk Notable fired + case created
//  5. Over time, old events expire → score decays automatically
package rba

import (
	"context"
	"fmt"
	"time"

	"github.com/watchtower/watchtower/internal/aitriage"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

// Assigner routes a case to an engineer. *assign.Engine satisfies it.
type Assigner interface {
	Route(c *models.Case) (assignee, reason string)
}

// Triager produces a plain-English triage summary for a fired notable.
// *aitriage.Summarizer satisfies it. Optional — wired via SetTriager.
type Triager interface {
	Summarize(ctx context.Context, in aitriage.NotableInput) (string, error)
}

// triageAlertLimit bounds how many recent alerts we feed the summarizer.
const triageAlertLimit = 20

const (
	defaultThreshold  = 100           // risk points to trigger a notable
	defaultDecayHours = 24            // risk events expire after 24h
	notableCooldown   = time.Hour     // minimum gap between notables for same entity
)

// Engine processes every alert and maintains entity risk scores.
type Engine struct {
	store    *store.Store
	logger   *zap.Logger
	assigner Assigner
	casesCfg config.CasesConfig
	triager  Triager
}

func NewEngine(st *store.Store, logger *zap.Logger) *Engine {
	return &Engine{store: st, logger: logger}
}

// SetAssigner wires the auto-assignment engine (optional).
func (e *Engine) SetAssigner(a Assigner) { e.assigner = a }

// SetTriager wires the Claude-backed triage summarizer (optional). When set,
// every fired notable gets an AI summary attached to its case asynchronously.
func (e *Engine) SetTriager(t Triager) { e.triager = t }

// SetCasesConfig provides the per-priority SLA windows for RBA-created cases.
func (e *Engine) SetCasesConfig(cfg config.CasesConfig) { e.casesCfg = cfg }

// OnAlert is called by the detection engine after every stored alert.
// It creates a risk event, recomputes the entity score, and fires a
// Risk Notable if the threshold is crossed.
func (e *Engine) OnAlert(alert *models.Alert, event *models.Event) {
	if alert.ID == 0 || alert.AgentID == "" {
		return
	}

	// Look up configured weight; fall back to level-derived default.
	weight := e.riskWeight(alert.RuleID, alert.Level)

	now := time.Now().UnixMilli()
	expiresAt := now + int64(defaultDecayHours)*3600*1000

	// Record risk event.
	riskEvent := &store.RbaRiskEvent{
		EntityID:   alert.AgentID,
		EntityType: "agent",
		RuleID:     alert.RuleID,
		AlertID:    alert.ID,
		RiskWeight: weight,
		Timestamp:  now,
		ExpiresAt:  expiresAt,
	}
	if err := e.store.InsertRbaRiskEvent(riskEvent); err != nil {
		e.logger.Warn("rba: failed to insert risk event", zap.Error(err))
		return
	}

	// Recompute current score from all unexpired events.
	score, err := e.store.ComputeEntityRiskScore(alert.AgentID)
	if err != nil {
		e.logger.Warn("rba: failed to compute risk score", zap.Error(err))
		return
	}

	// Load or initialise entity record.
	entity, _ := e.store.GetRbaEntityRisk(alert.AgentID)
	if entity.EntityID == "" {
		entity.EntityID = alert.AgentID
		entity.EntityType = "agent"
		entity.Threshold = defaultThreshold
	}
	entity.CurrentScore = score
	entity.LastEvent = now

	// Check threshold and cooldown.
	if score >= entity.Threshold {
		cooldownExpired := time.Since(time.UnixMilli(entity.LastNotable)) >= notableCooldown
		if cooldownExpired {
			e.fireNotable(entity, alert, score)
			entity.NotablesFired++
			entity.LastNotable = now
		}
	}

	if err := e.store.UpsertRbaEntityRisk(entity); err != nil {
		e.logger.Warn("rba: failed to upsert entity risk", zap.Error(err))
	}
}

// fireNotable creates a Risk Notable and auto-creates a linked case.
func (e *Engine) fireNotable(entity *store.RbaEntityRisk, alert *models.Alert, score int) {
	desc := fmt.Sprintf(
		"Entity %s crossed risk threshold: score=%d (threshold=%d). "+
			"Triggered by rule %d (level %d: %s).",
		entity.EntityID, score, entity.Threshold, alert.RuleID, alert.Level, alert.Title,
	)

	notable := &store.RbaNotable{
		EntityID:      entity.EntityID,
		EntityType:    entity.EntityType,
		RiskScore:     score,
		TriggerRuleID: alert.RuleID,
		Description:   desc,
	}
	notableID, err := e.store.InsertRbaNotable(notable)
	if err != nil {
		e.logger.Error("rba: failed to insert notable", zap.Error(err))
		return
	}

	e.logger.Info("rba: RISK NOTABLE fired",
		zap.String("entity", entity.EntityID),
		zap.Int("score", score),
		zap.Int("threshold", entity.Threshold),
		zap.Int64("notable_id", notableID),
	)

	// Auto-create a linked case.
	priority := riskToPriority(score)
	c := &models.Case{
		Title:       fmt.Sprintf("[RBA] Risk threshold exceeded: %s (score %d)", entity.EntityID, score),
		Description: desc,
		Status:      models.CaseStatusOpen,
		Priority:    priority,
		CreatedBy:   "rba-engine",
		Tags:        []string{"rba", "auto-created", entity.EntityType},
		AgentIDs:    []string{entity.EntityID},
	}
	// SLA deadline + ~80% warning from the per-priority window.
	if d := e.casesCfg.SLAFor(string(priority)); d > 0 {
		now := time.Now().UnixMilli()
		c.DueAt = now + d.Milliseconds()
		c.WarnAt = now + d.Milliseconds()*8/10
	}
	// Auto-assign before insert.
	if e.assigner != nil {
		if assignee, _ := e.assigner.Route(c); assignee != "" {
			c.Assignee = assignee
		} else {
			c.Tags = append(c.Tags, "unassigned-queue")
		}
	}
	caseID, err := e.store.CreateCase(c)
	if err != nil {
		e.logger.Warn("rba: failed to create case for notable", zap.Error(err))
	} else {
		e.store.UpdateRbaNotableCaseID(notableID, caseID)
		if c.Assignee != "" {
			_, _ = e.store.AddCaseHistory(&models.CaseHistory{
				CaseID: caseID, Actor: "auto", Action: "assigned", NewValue: c.Assignee,
			})
		}
		e.logger.Info("rba: auto-created case", zap.Int64("case_id", caseID), zap.String("assignee", c.Assignee))

		// Summarize the notable with Claude and attach it as a case note.
		// Runs off the alert path — Summarize is a network round-trip and must
		// not block the engine's OnAlert pipeline.
		if e.triager != nil {
			go e.triageCase(caseID, entity.EntityID, entity.EntityType, entity.Threshold, score)
		}
	}
}

// triageCase loads the entity's recent alerts, asks Claude for a triage
// summary, and writes it onto the case as a note. Best-effort: any failure is
// logged and the case still stands on its own.
func (e *Engine) triageCase(caseID int64, entityID, entityType string, threshold, score int) {
	alerts, err := e.store.ListAlerts(entityID, 0, triageAlertLimit, 0)
	if err != nil {
		e.logger.Warn("rba: triage could not load alerts", zap.Int64("case_id", caseID), zap.Error(err))
		return
	}
	lines := make([]aitriage.AlertLine, 0, len(alerts))
	for _, a := range alerts {
		lines = append(lines, aitriage.AlertLine{
			RuleID: a.RuleID,
			Level:  a.Level,
			Title:  a.Title,
			When:   time.UnixMilli(a.Timestamp),
		})
	}

	summary, err := e.triager.Summarize(context.Background(), aitriage.NotableInput{
		EntityID:   entityID,
		EntityType: entityType,
		RiskScore:  score,
		Threshold:  threshold,
		Alerts:     lines,
	})
	if err != nil {
		e.logger.Warn("rba: AI triage summarization failed", zap.Int64("case_id", caseID), zap.Error(err))
		return
	}

	if _, err := e.store.AddCaseNote(&models.CaseNote{
		CaseID:  caseID,
		Author:  "ai-triage",
		Content: "AI triage summary (Claude):\n\n" + summary,
	}); err != nil {
		e.logger.Warn("rba: failed to attach triage note", zap.Int64("case_id", caseID), zap.Error(err))
		return
	}
	e.logger.Info("rba: attached AI triage summary", zap.Int64("case_id", caseID))
}

// riskWeight returns the configured weight for a rule, or derives a default from level.
func (e *Engine) riskWeight(ruleID, level int) int {
	if w, err := e.store.GetRbaRuleWeight(ruleID); err == nil && w > 0 {
		return w
	}
	return levelToWeight(level)
}

// levelToWeight maps alert levels to risk point defaults.
func levelToWeight(level int) int {
	switch {
	case level >= 13:
		return 100
	case level >= 10:
		return 50
	case level >= 6:
		return 25
	default:
		return 10
	}
}

// riskToPriority maps a risk score to a case priority.
func riskToPriority(score int) models.CasePriority {
	switch {
	case score >= 200:
		return models.CasePriorityCritical
	case score >= 150:
		return models.CasePriorityHigh
	case score >= 100:
		return models.CasePriorityMedium
	default:
		return models.CasePriorityLow
	}
}
