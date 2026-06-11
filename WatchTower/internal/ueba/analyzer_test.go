package ueba

import (
	"testing"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
)

// fakeEmitter captures the alert/event the analyzer pushes and simulates the
// engine assigning a stored alert ID.
type fakeEmitter struct {
	alert    *models.Alert
	event    *models.Event
	assignID int64
}

func (f *fakeEmitter) EmitAlert(ev *models.Event, a *models.Alert) {
	f.event = ev
	f.alert = a
	a.ID = f.assignID
}

func TestEmitAlertForAnomalyAgentEntity(t *testing.T) {
	fe := &fakeEmitter{assignID: 4242}
	a := &Analyzer{emitter: fe}
	anomaly := &store.UebaAnomaly{
		EntityID:    "agent-7",
		EntityType:  "agent",
		AnomalyType: "data_exfiltration",
		Description: "100 MB egress in 1h",
		Severity:    "critical",
		Score:       40,
	}

	a.emitAlertForAnomaly(anomaly)

	if fe.alert == nil {
		t.Fatal("expected an alert to be emitted")
	}
	if fe.alert.AgentID != "agent-7" {
		t.Errorf("agent entity should set AgentID, got %q", fe.alert.AgentID)
	}
	if fe.alert.RuleID != 92021 {
		t.Errorf("data_exfiltration should map to rule 92021, got %d", fe.alert.RuleID)
	}
	if fe.alert.Level != 13 {
		t.Errorf("critical severity should map to level 13, got %d", fe.alert.Level)
	}
	if fe.alert.Title != "UEBA: Data Exfiltration" {
		t.Errorf("unexpected title %q", fe.alert.Title)
	}
	// Back-link: the analyzer must record the assigned alert ID on the anomaly.
	if anomaly.AlertID != 4242 {
		t.Errorf("expected anomaly.AlertID back-link 4242, got %d", anomaly.AlertID)
	}
	if fe.event == nil || fe.event.Type != "ueba.anomaly" {
		t.Error("expected a synthetic ueba.anomaly carrier event")
	}
}

func TestEmitAlertForAnomalyUserEntityHasNoAgentID(t *testing.T) {
	fe := &fakeEmitter{assignID: 1}
	a := &Analyzer{emitter: fe}
	a.emitAlertForAnomaly(&store.UebaAnomaly{
		EntityID:    "alice",
		EntityType:  "user",
		AnomalyType: "user_multiple_failures",
		Severity:    "high",
	})
	if fe.alert.AgentID != "" {
		t.Errorf("user entity must not set AgentID, got %q", fe.alert.AgentID)
	}
}

func TestEmitAlertForAnomalyNilEmitterNoPanic(t *testing.T) {
	a := &Analyzer{} // no emitter
	a.emitAlertForAnomaly(&store.UebaAnomaly{EntityType: "agent", EntityID: "x"})
}

func TestLevelFromSeverity(t *testing.T) {
	cases := map[string]int{"critical": 13, "high": 10, "medium": 7, "low": 4, "": 4}
	for sev, want := range cases {
		if got := levelFromSeverity(sev); got != want {
			t.Errorf("levelFromSeverity(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestHumanizeAnomaly(t *testing.T) {
	if got := humanizeAnomaly("brute_force_success"); got != "Brute Force Success" {
		t.Errorf("got %q", got)
	}
}

func TestSetConfigOverridesDefaultsAndKeepsZeros(t *testing.T) {
	a := NewAnalyzer(nil, nil, nil)
	// Sanity: defaults wired in NewAnalyzer.
	if a.spikeSigma != spikeThresholdSigma || a.minSamples != minSamplesForSpike ||
		a.entityBaselineDays != entityBaselineWindowDays || a.bruteForceFailMin != bruteForceFailThreshold {
		t.Fatalf("unexpected defaults: %+v", a)
	}

	// Partial override: set sigma + exfil only; the rest must keep defaults.
	a.SetConfig(config.UEBAConfig{SpikeSigma: 3.0, ExfilThresholdMB: 50})
	if a.spikeSigma != 3.0 {
		t.Errorf("spikeSigma override not applied: %v", a.spikeSigma)
	}
	if a.exfilBytes != int64(50)*1024*1024 {
		t.Errorf("exfil override wrong: %d", a.exfilBytes)
	}
	if a.minSamples != minSamplesForSpike {
		t.Errorf("unset min_samples should keep default, got %d", a.minSamples)
	}
	if a.entityBaselineDays != entityBaselineWindowDays {
		t.Errorf("unset entity_baseline_days should keep default, got %d", a.entityBaselineDays)
	}
}

func TestEntitySpikeFiresOnSelfBaseline(t *testing.T) {
	// Flat history at ~2/day, then a spike of 20 today.
	series := []float64{2, 1, 3, 2, 2, 1, 3, 20}
	z, fired := entitySpike(series, minSamplesForSpike, spikeThresholdSigma)
	if !fired {
		t.Fatalf("expected spike to fire, z=%.2f", z)
	}
	if z < spikeThresholdSigma {
		t.Errorf("z-score %.2f should clear threshold %.1f", z, spikeThresholdSigma)
	}
}

func TestEntitySpikeColdStart(t *testing.T) {
	// Fewer than minSamplesForSpike baseline days → never fires.
	if _, fired := entitySpike([]float64{1, 50}, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("cold start (too few baseline days) must not fire")
	}
}

func TestEntitySpikeFlatHistoryNoVariance(t *testing.T) {
	// Zero variance baseline → std 0 → no division-by-zero spike.
	if _, fired := entitySpike([]float64{5, 5, 5, 5, 5}, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("flat (zero-variance) baseline must not fire")
	}
}

func TestEntitySpikeNormalDayDoesNotFire(t *testing.T) {
	// Today within the host's normal range.
	if _, fired := entitySpike([]float64{4, 6, 5, 7, 5, 6}, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("a normal day should not fire a spike")
	}
}

func TestLastNDayKeysOrderedEndingToday(t *testing.T) {
	keys := lastNDayKeys(30)
	if len(keys) != 30 {
		t.Fatalf("expected 30 keys, got %d", len(keys))
	}
	today := time.Now().UTC().Format("2006-01-02")
	if keys[len(keys)-1] != today {
		t.Errorf("last key should be today %s, got %s", today, keys[len(keys)-1])
	}
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			t.Errorf("keys must be strictly ascending: %s !< %s", keys[i-1], keys[i])
		}
	}
}

func TestSameWeekdaySamplesStepsBackBySeven(t *testing.T) {
	// 15-day series, today = index 14. Same-weekday priors: 7 and 0.
	series := make([]float64, 15)
	for i := range series {
		series[i] = float64(i)
	}
	got := sameWeekdaySamples(series)
	want := []float64{7, 0} // index 14-7=7, then 0
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sample[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestSpikeWithSeasonalityUsesWeekdayBaseline(t *testing.T) {
	// 8 weeks (56 days). Same-weekday-as-today is naturally busy (~20, with
	// realistic spread); every other day is quiet (~2). A normal busy day must
	// NOT fire against the same-weekday baseline, even though it's a huge
	// outlier against a flat all-days baseline.
	series := make([]float64, 56)
	todayIdx := len(series) - 1
	weekdayVals := []float64{15, 18, 20, 22, 25, 19, 21} // mean ~20, std ~3
	wi := 0
	for i := range series {
		if (todayIdx-i)%7 == 0 { // same weekday as today
			series[i] = weekdayVals[wi%len(weekdayVals)]
			wi++
		} else {
			series[i] = 2
		}
	}
	series[todayIdx] = 21 // normal busy-day volume

	_, fired, basis := spikeWithSeasonality(series, minSamplesForSpike, spikeThresholdSigma)
	if basis != "same-weekday" {
		t.Fatalf("expected same-weekday basis, got %q", basis)
	}
	if fired {
		t.Error("a normal busy day should not fire against a same-weekday baseline")
	}

	// Same series but today jumps to 60 — abnormal even for this weekday → fires.
	series[todayIdx] = 60
	z, fired2, basis2 := spikeWithSeasonality(series, minSamplesForSpike, spikeThresholdSigma)
	if basis2 != "same-weekday" || !fired2 {
		t.Errorf("abnormal busy day should fire on same-weekday basis (basis=%q fired=%v z=%.1f)", basis2, fired2, z)
	}
}

func TestSpikeWithSeasonalityFallsBackToDaily(t *testing.T) {
	// Too few same-weekday samples (only 10 days) → fall back to daily basis.
	series := []float64{2, 1, 3, 2, 2, 1, 3, 2, 1, 40}
	_, fired, basis := spikeWithSeasonality(series, minSamplesForSpike, spikeThresholdSigma)
	if basis != "daily" {
		t.Errorf("short history should fall back to daily basis, got %q", basis)
	}
	if !fired {
		t.Error("clear spike should fire via the daily fallback")
	}
}

func TestPeerGroupOutlierFiresWithinCohort(t *testing.T) {
	// A web-server farm where peers sit at ~10 alerts and one host spikes to 80.
	cohort := []float64{9, 11, 10, 12, 8, 80}
	z, fired := peerGroupOutlier(80, cohort, minSamplesForSpike, spikeThresholdSigma)
	if !fired {
		t.Fatalf("expected outlier to fire, z=%.2f", z)
	}
	// A normal member must not fire against the same cohort.
	if _, fired := peerGroupOutlier(10, cohort, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("a normal cohort member should not fire")
	}
}

func TestPeerGroupOutlierColdAndFlat(t *testing.T) {
	// Cohort smaller than minSamples → never fires (can't form a baseline).
	if _, fired := peerGroupOutlier(99, []float64{1, 99}, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("tiny cohort must not fire")
	}
	// Zero-variance cohort → no division-by-zero spike.
	if _, fired := peerGroupOutlier(5, []float64{5, 5, 5, 5}, minSamplesForSpike, spikeThresholdSigma); fired {
		t.Error("flat cohort must not fire")
	}
}

func TestPeerGroupOutlierHonorsSigma(t *testing.T) {
	// Same data, stricter sigma should suppress a borderline outlier.
	cohort := []float64{8, 10, 12, 9, 11, 22}
	if _, fired := peerGroupOutlier(22, cohort, minSamplesForSpike, 2.0); !fired {
		t.Error("expected fire at 2σ")
	}
	if _, fired := peerGroupOutlier(22, cohort, minSamplesForSpike, 4.0); fired {
		t.Error("4σ should suppress the borderline outlier")
	}
}

func TestAnomalyRuleIDsAreDistinct(t *testing.T) {
	types := []string{"alert_spike", "critical_alert_burst", "entity_alert_spike", "peer_group_spike"}
	seen := map[int]string{}
	for _, ty := range types {
		id := anomalyRuleID(ty)
		if prev, dup := seen[id]; dup {
			t.Errorf("rule ID %d collides: %q and %q", id, prev, ty)
		}
		seen[id] = ty
	}
}

func TestDensifyFillsMissingDaysWithZero(t *testing.T) {
	days := []string{"2026-06-01", "2026-06-02", "2026-06-03"}
	series := densify(map[string]int{"2026-06-01": 4, "2026-06-03": 9}, days)
	want := []float64{4, 0, 9}
	for i := range want {
		if series[i] != want[i] {
			t.Errorf("densify[%d] = %v, want %v", i, series[i], want[i])
		}
	}
}

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
