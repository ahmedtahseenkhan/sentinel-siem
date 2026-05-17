package dedup

import (
	"testing"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

func TestShouldSuppressFirstAlertPasses(t *testing.T) {
	m := New(5*time.Minute, zap.NewNop())
	defer m.Stop()

	alert := &models.Alert{
		RuleID:    100,
		AgentID:   "agent-a",
		Title:     "Test alert",
		EventData: `{"srcip":"1.2.3.4"}`,
	}
	if m.ShouldSuppress(alert) {
		t.Fatal("first alert must not be suppressed")
	}
}

func TestShouldSuppressDuplicateWithinWindow(t *testing.T) {
	m := New(5*time.Minute, zap.NewNop())
	defer m.Stop()

	alert := &models.Alert{
		RuleID:    100,
		AgentID:   "agent-a",
		Title:     "Test alert",
		EventData: `{"srcip":"1.2.3.4"}`,
	}
	_ = m.ShouldSuppress(alert) // record first
	if !m.ShouldSuppress(alert) {
		t.Fatal("duplicate alert within window must be suppressed")
	}
}

func TestShouldSuppressDifferentAgentsNotSuppressed(t *testing.T) {
	m := New(5*time.Minute, zap.NewNop())
	defer m.Stop()

	a := &models.Alert{RuleID: 100, AgentID: "agent-a", Title: "X", EventData: `{"srcip":"1.2.3.4"}`}
	b := &models.Alert{RuleID: 100, AgentID: "agent-b", Title: "X", EventData: `{"srcip":"1.2.3.4"}`}
	_ = m.ShouldSuppress(a)
	if m.ShouldSuppress(b) {
		t.Fatal("alerts from different agents must not be suppressed by each other")
	}
}

func TestShouldSuppressDifferentRulesNotSuppressed(t *testing.T) {
	m := New(5*time.Minute, zap.NewNop())
	defer m.Stop()

	a := &models.Alert{RuleID: 100, AgentID: "agent-a", Title: "X", EventData: `{"srcip":"1.2.3.4"}`}
	b := &models.Alert{RuleID: 200, AgentID: "agent-a", Title: "X", EventData: `{"srcip":"1.2.3.4"}`}
	_ = m.ShouldSuppress(a)
	if m.ShouldSuppress(b) {
		t.Fatal("alerts from different rules must not be suppressed by each other")
	}
}

func TestShouldSuppressDifferentDiscriminatorNotSuppressed(t *testing.T) {
	m := New(5*time.Minute, zap.NewNop())
	defer m.Stop()

	a := &models.Alert{RuleID: 100, AgentID: "agent-a", Title: "X", EventData: `{"srcip":"1.2.3.4"}`}
	b := &models.Alert{RuleID: 100, AgentID: "agent-a", Title: "X", EventData: `{"srcip":"5.6.7.8"}`}
	_ = m.ShouldSuppress(a)
	if m.ShouldSuppress(b) {
		t.Fatal("alerts with different discriminator values must not be suppressed")
	}
}
