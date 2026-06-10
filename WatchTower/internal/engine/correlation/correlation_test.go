package correlation

import (
	"testing"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

func evt(agentID, srcIP string) *models.Event {
	return &models.Event{
		AgentID: agentID,
		Fields:  map[string]interface{}{"src_ip": srcIP},
	}
}

// fireOnNth feeds n identical events and returns the 1-based index at which
// ShouldFire first returns true (0 = never fired across n events).
func fireOnNth(m *Manager, rule *models.Rule, e *models.Event, n int) int {
	for i := 1; i <= n; i++ {
		if m.ShouldFire(rule, e) {
			return i
		}
	}
	return 0
}

// The bug this guards: rules authored with the legacy `correlation:` block
// were silently ignored (struct only had `threshold:`), so they fired on the
// FIRST matching event instead of the Nth. This proves correlation: now counts.
func TestCorrelationBlockFiresOnThreshold(t *testing.T) {
	m := New(zap.NewNop())
	defer m.Stop()

	rule := &models.Rule{
		ID:          7000,
		Correlation: &models.RuleCorrelation{Window: "5m", Threshold: 5, GroupBy: []string{"src_ip"}},
	}
	if got := fireOnNth(m, rule, evt("a1", "10.0.0.1"), 5); got != 5 {
		t.Fatalf("correlation rule should fire on the 5th event, fired on #%d", got)
	}
}

// Backward compatibility: the original threshold: block must still work.
func TestThresholdBlockStillWorks(t *testing.T) {
	m := New(zap.NewNop())
	defer m.Stop()

	rule := &models.Rule{
		ID:        7001,
		Threshold: &models.RuleThreshold{Count: 3, PeriodSecs: 300, GroupBy: "src_ip"},
	}
	if got := fireOnNth(m, rule, evt("a1", "10.0.0.2"), 3); got != 3 {
		t.Fatalf("threshold rule should fire on the 3rd event, fired on #%d", got)
	}
}

// group_by must isolate counters: two distinct source IPs each need their own
// threshold and must not pool into one.
func TestGroupByIsolatesCounters(t *testing.T) {
	m := New(zap.NewNop())
	defer m.Stop()

	rule := &models.Rule{
		ID:          7002,
		Correlation: &models.RuleCorrelation{Window: "5m", Threshold: 3, GroupBy: []string{"src_ip"}},
	}
	// 2 hits from .10 and 2 from .20 — neither group reaches 3, so no fire.
	for i := 0; i < 2; i++ {
		if m.ShouldFire(rule, evt("a1", "10.0.0.10")) || m.ShouldFire(rule, evt("a1", "10.0.0.20")) {
			t.Fatal("fired before any single group reached the threshold")
		}
	}
	// 3rd hit on .10 tips only that group over.
	if !m.ShouldFire(rule, evt("a1", "10.0.0.10")) {
		t.Fatal(".10 should fire on its 3rd hit")
	}
}

// A rule with neither block is a pass-through (fires every time).
func TestNoCorrelationPassesThrough(t *testing.T) {
	m := New(zap.NewNop())
	defer m.Stop()

	rule := &models.Rule{ID: 7003}
	if !m.ShouldFire(rule, evt("a1", "10.0.0.3")) {
		t.Fatal("rule without threshold/correlation must pass through")
	}
}
