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
	"fmt"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

const (
	defaultThreshold  = 100           // risk points to trigger a notable
	defaultDecayHours = 24            // risk events expire after 24h
	notableCooldown   = time.Hour     // minimum gap between notables for same entity
)

// Engine processes every alert and maintains entity risk scores.
type Engine struct {
	store  *store.Store
	logger *zap.Logger
}

func NewEngine(st *store.Store, logger *zap.Logger) *Engine {
	return &Engine{store: st, logger: logger}
}

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
	c := &models.Case{
		Title:       fmt.Sprintf("[RBA] Risk threshold exceeded: %s (score %d)", entity.EntityID, score),
		Description: desc,
		Status:      models.CaseStatusOpen,
		Priority:    riskToPriority(score),
		CreatedBy:   "rba-engine",
		Tags:        []string{"rba", "auto-created", entity.EntityType},
		AgentIDs:    []string{entity.EntityID},
	}
	caseID, err := e.store.CreateCase(c)
	if err != nil {
		e.logger.Warn("rba: failed to create case for notable", zap.Error(err))
	} else {
		e.store.UpdateRbaNotableCaseID(notableID, caseID)
		e.logger.Info("rba: auto-created case", zap.Int64("case_id", caseID))
	}
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
