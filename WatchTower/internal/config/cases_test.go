package config

import (
	"testing"
	"time"
)

// The local stack runs WatchTower with no config file (env-only), so the
// auto-create hook is only reachable if DefaultConfig enables it. These tests
// lock that in.
func TestDefaultConfig_AutoCreateEnabled(t *testing.T) {
	c := DefaultConfig()
	if !c.Cases.AutoCreate.Enabled {
		t.Fatal("expected auto-create enabled by default")
	}
	if got := c.Cases.MinLevelOrDefault(); got != 10 {
		t.Fatalf("expected default min_level 10, got %d", got)
	}
	if got := c.Cases.SLAFor("critical"); got != time.Hour {
		t.Fatalf("expected critical SLA 1h, got %s", got)
	}
}

func TestEnvOverride_DisablesAutoCreate(t *testing.T) {
	t.Setenv("WATCHTOWER_CASES_AUTO_CREATE", "false")
	t.Setenv("WATCHTOWER_CASES_MIN_LEVEL", "12")
	c := DefaultConfig()
	ApplyEnvOverrides(c)

	if c.Cases.AutoCreate.Enabled {
		t.Fatal("expected env to disable auto-create")
	}
	if c.Cases.AutoCreate.MinLevel != 12 {
		t.Fatalf("expected env min_level 12, got %d", c.Cases.AutoCreate.MinLevel)
	}
}

func TestSLAFor_DisableAndDefault(t *testing.T) {
	c := CasesConfig{}
	if got := c.SLAFor("high"); got != 4*time.Hour {
		t.Fatalf("empty high should default to 4h, got %s", got)
	}
	c.SLA.High = "none"
	if got := c.SLAFor("high"); got != 0 {
		t.Fatalf(`"none" should disable SLA (0), got %s`, got)
	}
	c.SLA.High = "30m"
	if got := c.SLAFor("high"); got != 30*time.Minute {
		t.Fatalf("explicit 30m, got %s", got)
	}
}
