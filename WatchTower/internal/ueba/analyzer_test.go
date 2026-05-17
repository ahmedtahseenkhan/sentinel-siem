package ueba

import "testing"

func TestComputeRiskScoreCapsAt100(t *testing.T) {
	// Massive values should still cap at 100
	got := computeRiskScore(10000, 10000, 100, 100)
	if got != 100 {
		t.Errorf("expected score to cap at 100, got %d", got)
	}
}

func TestComputeRiskScoreZeroIsZero(t *testing.T) {
	if got := computeRiskScore(0, 0, 0, 0); got != 0 {
		t.Errorf("expected score 0, got %d", got)
	}
}

func TestComputeRiskScoreCriticalAlertsDominate(t *testing.T) {
	// 5 critical alerts → 40 from critical
	got := computeRiskScore(5, 5, 0, 0)
	// total: 5*0.5=2 (capped 30) + 5*8=40 (capped 40) + 0 + 0 = 42
	if got < 40 || got > 50 {
		t.Errorf("expected ~42 for 5 critical alerts, got %d", got)
	}
}

func TestRiskLevelFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "low"},
		{24, "low"},
		{25, "medium"},
		{49, "medium"},
		{50, "high"},
		{74, "high"},
		{75, "critical"},
		{100, "critical"},
	}
	for _, c := range cases {
		if got := riskLevelFromScore(c.score); got != c.want {
			t.Errorf("riskLevelFromScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestSeverityFromZScore(t *testing.T) {
	cases := []struct {
		z    float64
		want string
	}{
		{1.5, "low"},
		{2.0, "medium"},
		{2.9, "medium"},
		{3.0, "high"},
		{3.9, "high"},
		{4.0, "critical"},
		{10.0, "critical"},
	}
	for _, c := range cases {
		if got := severityFromZScore(c.z); got != c.want {
			t.Errorf("severityFromZScore(%.1f) = %q, want %q", c.z, got, c.want)
		}
	}
}

func TestMeanStdEmpty(t *testing.T) {
	avg, std := meanStd(nil)
	if avg != 0 || std != 0 {
		t.Errorf("expected (0, 0) for empty input, got (%f, %f)", avg, std)
	}
}

func TestMeanStdSingleValue(t *testing.T) {
	avg, std := meanStd([]float64{5})
	if avg != 5 || std != 0 {
		t.Errorf("expected (5, 0), got (%f, %f)", avg, std)
	}
}

func TestMeanStdMultipleValues(t *testing.T) {
	// values: 2, 4, 4, 4, 5, 5, 7, 9 → mean=5, popstd=2
	avg, std := meanStd([]float64{2, 4, 4, 4, 5, 5, 7, 9})
	if avg != 5 {
		t.Errorf("expected mean 5, got %f", avg)
	}
	if std < 1.9 || std > 2.1 {
		t.Errorf("expected std ≈ 2.0, got %f", std)
	}
}

func TestIsRareProcess(t *testing.T) {
	if !isSuspiciousProcess("mimikatz.exe") {
		t.Error("mimikatz.exe should be flagged as rare/suspicious")
	}
	if !isSuspiciousProcess("nc.exe") {
		t.Error("nc.exe should be flagged as rare/suspicious")
	}
	if isSuspiciousProcess("chrome.exe") {
		t.Error("chrome.exe should NOT be flagged")
	}
	if isSuspiciousProcess("") {
		t.Error("empty should NOT be flagged")
	}
}
