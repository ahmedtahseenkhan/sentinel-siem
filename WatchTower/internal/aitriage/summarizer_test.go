package aitriage

import (
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

func TestPromptIncludesEntityAndAlerts(t *testing.T) {
	in := NotableInput{
		EntityID:   "host-42",
		EntityType: "agent",
		RiskScore:  140,
		Threshold:  100,
		Alerts: []AlertLine{
			{RuleID: 92013, Level: 12, Title: "Brute force success", When: time.Unix(1700000000, 0)},
			{RuleID: 5710, Level: 10, Title: "Multiple failed logons", When: time.Unix(1699999000, 0)},
		},
	}
	p := in.prompt()

	for _, want := range []string{"host-42", "agent", "140", "100", "Brute force success", "92013", "Multiple failed logons"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q\n---\n%s", want, p)
		}
	}
	if got := strings.Count(p, "- ["); got != 2 {
		t.Errorf("expected 2 alert lines, got %d", got)
	}
}

func TestPromptNoAlerts(t *testing.T) {
	p := NotableInput{EntityID: "u1", EntityType: "user", RiskScore: 100, Threshold: 100}.prompt()
	if !strings.Contains(p, "No contributing alerts") {
		t.Errorf("expected no-alerts notice, got:\n%s", p)
	}
}

func TestNewSummarizerDefaults(t *testing.T) {
	s := NewSummarizer("key", "", 0, nil)
	if s.model != anthropic.ModelClaudeOpus4_8 {
		t.Errorf("empty model should default to Opus 4.8, got %q", s.model)
	}
	if s.timeout != 30*time.Second {
		t.Errorf("non-positive timeout should default to 30s, got %s", s.timeout)
	}
}

func TestNewSummarizerHonorsModel(t *testing.T) {
	s := NewSummarizer("key", "claude-haiku-4-5", 5*time.Second, nil)
	if string(s.model) != "claude-haiku-4-5" {
		t.Errorf("model override not honored, got %q", s.model)
	}
	if s.timeout != 5*time.Second {
		t.Errorf("timeout override not honored, got %s", s.timeout)
	}
}
