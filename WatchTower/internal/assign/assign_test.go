package assign

import (
	"testing"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type fakeStore struct {
	engineers []*models.SOCEngineer
	onShift   map[string]bool
}

func (f *fakeStore) ListSOCEngineers(bool) ([]*models.SOCEngineer, error) { return f.engineers, nil }
func (f *fakeStore) OnShiftSams(int, int) (map[string]bool, error)        { return f.onShift, nil }

func eng(sam string, tier, load, max int, skills ...string) *models.SOCEngineer {
	return &models.SOCEngineer{SamAccount: sam, Tier: tier, OpenLoad: load, MaxLoad: max, Active: true, SkillGroups: skills}
}

func newEngine(engs []*models.SOCEngineer, onShift map[string]bool) *Engine {
	return New(&fakeStore{engineers: engs, onShift: onShift}, zap.NewNop())
}

func TestAssign_SkillTierLeastLoaded(t *testing.T) {
	e := newEngine(
		[]*models.SOCEngineer{
			eng("alice", 2, 5, 25, "windows"),
			eng("bob", 2, 2, 25, "windows"), // same skill+tier, lower load → wins
			eng("carol", 2, 0, 25, "cloud"), // wrong skill
		},
		map[string]bool{"alice": false, "bob": false, "carol": false},
	)
	c := &models.Case{Priority: models.CasePriorityHigh, Tags: []string{"windows"}}
	if r := e.Assign(c); r.Assignee != "bob" {
		t.Fatalf("expected bob (skill+least-loaded), got %q (%s)", r.Assignee, r.Reason)
	}
}

func TestAssign_SeverityRequiresSeniorTier(t *testing.T) {
	e := newEngine(
		[]*models.SOCEngineer{
			eng("junior", 1, 0, 25, "windows"), // too junior for critical
			eng("senior", 3, 4, 25, "windows"),
		},
		map[string]bool{"junior": false, "senior": false},
	)
	c := &models.Case{Priority: models.CasePriorityCritical, Tags: []string{"windows"}}
	if r := e.Assign(c); r.Assignee != "senior" {
		t.Fatalf("critical must go to tier-3 senior, got %q", r.Assignee)
	}
}

func TestAssign_SkippedWhenOverloaded_FallsBackToOnCall(t *testing.T) {
	e := newEngine(
		[]*models.SOCEngineer{
			eng("busy", 2, 25, 25, "windows"), // at max load → skipped
			eng("oncall", 3, 9, 25, "cloud"),  // on-call, different skill
		},
		map[string]bool{"oncall": true}, // only oncall is on shift, with on_call=true
	)
	c := &models.Case{Priority: models.CasePriorityHigh, Tags: []string{"windows"}}
	r := e.Assign(c)
	if r.Assignee != "oncall" {
		t.Fatalf("expected on-call fallback, got %q (%s)", r.Assignee, r.Reason)
	}
}

func TestAssign_FallbackQueueWhenNobody(t *testing.T) {
	e := newEngine([]*models.SOCEngineer{eng("alice", 1, 0, 25, "windows")},
		map[string]bool{}) // nobody on shift
	r := e.Assign(&models.Case{Priority: models.CasePriorityLow})
	if r.Assignee != "" {
		t.Fatalf("expected fallback queue (empty assignee), got %q", r.Assignee)
	}
}

func TestTierForSeverity(t *testing.T) {
	for p, want := range map[string]int{"critical": 3, "high": 2, "medium": 1, "low": 1, "": 1} {
		if got := TierForSeverity(p); got != want {
			t.Errorf("%q: want %d got %d", p, want, got)
		}
	}
}
