// Package assign routes a newly-created case to a SOC engineer: skill match →
// severity-to-tier → on-shift/on-call filter → least-loaded, with a fallback
// queue so a case is never silently dropped.
//
// It runs at every case-creation path (casegen, RBA, manual/XDR via the API),
// so assignment is decided in exactly one place.
package assign

import (
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// Store is the subset of *store.Store the engine needs (interface for testing).
type Store interface {
	ListSOCEngineers(activeOnly bool) ([]*models.SOCEngineer, error)
	OnShiftSams(weekday, nowMin int) (map[string]bool, error)
}

type Engine struct {
	store  Store
	logger *zap.Logger
}

func New(st Store, logger *zap.Logger) *Engine { return &Engine{store: st, logger: logger} }

// Result is the routing decision. Assignee == "" means the fallback queue.
type Result struct {
	Assignee string
	Tier     int
	Reason   string
}

// Assign routes a case using its severity to set the minimum tier.
func (e *Engine) Assign(c *models.Case) Result {
	return e.AssignWithMinTier(c, TierForSeverity(string(c.Priority)))
}

// Route is the convenience form used by the case-creation paths: returns the
// chosen assignee ("" = fallback queue) and a human-readable reason.
func (e *Engine) Route(c *models.Case) (assignee, reason string) {
	r := e.Assign(c)
	return r.Assignee, r.Reason
}

// AssignWithMinTier routes a case requiring at least minTier. Used directly by
// SLA escalation to bump a breached case to a more senior engineer.
func (e *Engine) AssignWithMinTier(c *models.Case, minTier int) Result {
	now := time.Now().UTC()
	weekday := int(now.Weekday())
	nowMin := now.Hour()*60 + now.Minute()

	onShift, err := e.store.OnShiftSams(weekday, nowMin)
	if err != nil {
		e.logger.Warn("assign: on-shift lookup failed", zap.Error(err))
		onShift = map[string]bool{}
	}
	engineers, err := e.store.ListSOCEngineers(true)
	if err != nil {
		e.logger.Warn("assign: roster lookup failed", zap.Error(err))
		return Result{Reason: "roster lookup failed — fallback queue"}
	}

	// Derive the required skill from the case tags, matched against the skills
	// the roster actually has (so nothing is hard-coded).
	skillSet := map[string]bool{}
	for _, en := range engineers {
		for _, s := range en.SkillGroups {
			skillSet[strings.ToLower(s)] = true
		}
	}
	skill := ""
	for _, t := range c.Tags {
		if skillSet[strings.ToLower(t)] {
			skill = strings.ToLower(t)
			break
		}
	}

	pick := func(ok func(*models.SOCEngineer) bool) *models.SOCEngineer {
		var best *models.SOCEngineer
		for _, en := range engineers {
			if !ok(en) {
				continue
			}
			if best == nil || en.OpenLoad < best.OpenLoad {
				best = en
			}
		}
		return best
	}
	onShiftAny := func(en *models.SOCEngineer) bool { _, in := onShift[en.SamAccount]; return in }
	onCall := func(en *models.SOCEngineer) bool { return onShift[en.SamAccount] }
	tierOK := func(en *models.SOCEngineer) bool { return en.Tier >= minTier }
	underLoad := func(en *models.SOCEngineer) bool { return en.OpenLoad < en.MaxLoad }
	hasSkill := func(en *models.SOCEngineer) bool { return skill == "" || containsFold(en.SkillGroups, skill) }

	// 1) Ideal: on shift, right skill, senior enough, under load.
	if b := pick(func(en *models.SOCEngineer) bool {
		return onShiftAny(en) && hasSkill(en) && tierOK(en) && underLoad(en)
	}); b != nil {
		return Result{b.SamAccount, b.Tier, "on-shift, skill+tier match, least-loaded"}
	}
	// 2) Relax the skill requirement.
	if b := pick(func(en *models.SOCEngineer) bool {
		return onShiftAny(en) && tierOK(en) && underLoad(en)
	}); b != nil {
		return Result{b.SamAccount, b.Tier, "on-shift, tier match (no skill), least-loaded"}
	}
	// 3) On-call escalation: ignore skill + load cap.
	if b := pick(func(en *models.SOCEngineer) bool { return onCall(en) && tierOK(en) }); b != nil {
		return Result{b.SamAccount, b.Tier, "on-call escalation"}
	}
	// 4) Nobody available → fallback queue.
	return Result{Reason: "no available engineer — fallback queue"}
}

// TierForSeverity maps a case priority to the minimum engineer tier.
func TierForSeverity(priority string) int {
	switch strings.ToLower(priority) {
	case "critical":
		return 3
	case "high":
		return 2
	default:
		return 1
	}
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
