// Package ueba implements User and Entity Behavior Analytics for Sentinel SIEM.
// It runs statistical baseline computation on the PostgreSQL alerts table,
// detects anomalies when current activity deviates significantly from the
// historical norm, and maintains rolling risk scores for every agent and user.
//
// Anomaly detection uses the 2-sigma rule:
//
//	anomaly when: current_value > baseline_avg + 2 * baseline_std_dev
//
// Risk scores are computed from alert volume, severity, and anomaly count.
package ueba

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

// AlertEmitter surfaces a detected anomaly as a first-class alert through the
// engine's full downstream pipeline (store, RBA risk accrual, notify, cases).
// *engine.Engine satisfies it via EmitAlert. Kept as a local interface so the
// ueba package does not import engine (which would create a cycle: engine
// already depends on ueba's EventCollector via its UebaHook interface).
type AlertEmitter interface {
	EmitAlert(event *models.Event, a *models.Alert)
}

const (
	baselineWindowDays       = 7
	entityBaselineWindowDays = 56 // 8 weeks — per-entity self-baseline; enough same-weekday samples for day-of-week seasonality
	analyzeInterval          = time.Hour
	spikeThresholdSigma      = 2.0
	minSamplesForSpike       = 3
	exfilThresholdBytes      = 100 * 1024 * 1024 // 100 MB/hour triggers exfiltration alert
	bruteForceFailThreshold  = 3                 // N failures from same IP before success = brute force
)

// Analyzer periodically computes UEBA baselines, detects anomalies, and
// updates entity risk scores.
type Analyzer struct {
	store     *store.Store
	logger    *zap.Logger
	collector *EventCollector // may be nil if not wired
	emitter   AlertEmitter    // may be nil; when set, anomalies become alerts

	// Tunable statistical thresholds, resolved from config (defaults set in
	// NewAnalyzer, overridden by SetConfig).
	spikeSigma         float64
	minSamples         int
	entityBaselineDays int
	exfilBytes         int64
	bruteForceFailMin  int

	// knownHashes tracks process sha256 hashes seen across analysis cycles
	// so we can flag genuinely first-seen executables on each agent.
	hashMu      sync.Mutex
	knownHashes map[string]map[string]bool // agentID → set of known sha256
}

func NewAnalyzer(st *store.Store, logger *zap.Logger, collector *EventCollector) *Analyzer {
	return &Analyzer{
		store:              st,
		logger:             logger,
		collector:          collector,
		knownHashes:        make(map[string]map[string]bool),
		spikeSigma:         spikeThresholdSigma,
		minSamples:         minSamplesForSpike,
		entityBaselineDays: entityBaselineWindowDays,
		exfilBytes:         exfilThresholdBytes,
		bruteForceFailMin:  bruteForceFailThreshold,
	}
}

// SetConfig overrides the analyzer's statistical thresholds from operator
// config. Non-positive fields are ignored so a partial config keeps defaults.
func (a *Analyzer) SetConfig(cfg config.UEBAConfig) {
	if cfg.SpikeSigma > 0 {
		a.spikeSigma = cfg.SpikeSigma
	}
	if cfg.MinSamples > 0 {
		a.minSamples = cfg.MinSamples
	}
	if cfg.EntityBaselineDays > 0 {
		a.entityBaselineDays = cfg.EntityBaselineDays
	}
	if cfg.ExfilThresholdMB > 0 {
		a.exfilBytes = int64(cfg.ExfilThresholdMB) * 1024 * 1024
	}
	if cfg.BruteForceFailMin > 0 {
		a.bruteForceFailMin = cfg.BruteForceFailMin
	}
}

// SetEmitter wires an AlertEmitter so detected anomalies surface as first-class
// alerts (and accrue RBA risk). Safe to leave unset — anomalies are still
// persisted to the ueba_anomalies table either way.
func (a *Analyzer) SetEmitter(e AlertEmitter) { a.emitter = e }

// Start runs the analyze loop until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) {
	a.analyze()
	ticker := time.NewTicker(analyzeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.analyze()
		}
	}
}

// Analyze triggers an immediate analysis cycle (exposed for the API).
func (a *Analyzer) Analyze() {
	a.analyze()
}

func (a *Analyzer) analyze() {
	a.logger.Debug("ueba: starting analysis cycle")
	start := time.Now()

	// ── Alert-based analysis (existing) ───────────────────────────────────────
	stats, err := a.store.AlertStatsPerEntity(baselineWindowDays)
	if err != nil {
		a.logger.Error("ueba: failed to fetch alert stats", zap.Error(err))
		return
	}

	totalValues := make([]float64, 0, len(stats))
	for _, s := range stats {
		totalValues = append(totalValues, float64(s["total"].(int)))
	}
	globalAvg, globalStd := meanStd(totalValues)

	// Per-entity 7d totals, reused below for peer-group outlier detection.
	entityTotals := make(map[string]int, len(stats))

	for _, s := range stats {
		agentID := s["agent_id"].(string)
		total := s["total"].(int)
		entityTotals[agentID] = total
		critCount := s["critical_count"].(int)
		maxLevel := s["max_level"].(int)
		lastAlert := s["last_alert"].(int64)

		baseline := &store.UebaBaseline{
			EntityID:    agentID,
			EntityType:  "agent",
			Metric:      "alert_rate_7d",
			AvgValue:    globalAvg,
			StdDev:      globalStd,
			SampleCount: len(stats),
		}
		_ = a.store.UpsertUebaBaseline(baseline)

		anomalyCount := 0
		if len(stats) >= a.minSamples && globalStd > 0 {
			zScore := (float64(total) - globalAvg) / globalStd
			if zScore >= a.spikeSigma {
				severity := severityFromZScore(zScore)
				desc := fmt.Sprintf(
					"Alert spike: %d alerts in 7d (%.1fx above average of %.0f)",
					total, float64(total)/math.Max(globalAvg, 1), globalAvg,
				)
				anomaly := &store.UebaAnomaly{
					EntityID:    agentID,
					EntityType:  "agent",
					AnomalyType: "alert_spike",
					Description: desc,
					Severity:    severity,
					Score:       int(math.Min(50, zScore*10)),
				}
				if err := a.insertAnomaly(anomaly); err == nil {
					anomalyCount++
				}
			}
		}

		if critCount >= 5 {
			anomaly := &store.UebaAnomaly{
				EntityID:    agentID,
				EntityType:  "agent",
				AnomalyType: "critical_alert_burst",
				Description: fmt.Sprintf("%d critical alerts in last 7 days", critCount),
				Severity:    "high",
				Score:       int(math.Min(40, float64(critCount)*4)),
			}
			if err := a.insertAnomaly(anomaly); err == nil {
				anomalyCount++
			}
		}

		riskScore := computeRiskScore(total, critCount, maxLevel, anomalyCount)
		riskLevel := riskLevelFromScore(riskScore)
		rs := &store.UebaRiskScore{
			EntityID:        agentID,
			EntityType:      "agent",
			RiskScore:       riskScore,
			RiskLevel:       riskLevel,
			AlertCount7d:    total,
			CriticalCount7d: critCount,
			AnomalyCount7d:  anomalyCount,
			LastAlert:       lastAlert,
		}
		if err := a.store.UpsertUebaRiskScore(rs); err != nil {
			a.logger.Warn("ueba: risk score upsert failed",
				zap.String("entity", agentID), zap.Error(err))
		}
	}

	// ── Event-based analysis (new) ─────────────────────────────────────────────
	if a.collector != nil {
		snap := a.collector.Snapshot()
		a.analyzeLoginBehavior(snap)
		a.analyzeNetworkBehavior(snap)
		a.analyzeProcessBehavior(snap)
		a.analyzeUserBehavior(snap)
	}

	// ── Per-entity self-baseline (new) ─────────────────────────────────────────
	// The block above compares an entity to its *peers* (cross-entity mean).
	// This compares each entity to its *own* recent history — catching a host
	// that is abnormally noisy for itself even if quiet relative to the fleet.
	a.analyzePerEntityBaseline()

	// ── Peer-group outliers (new) ──────────────────────────────────────────────
	// Refines the fleet-wide spike: compares each grouped host to others in its
	// *same role group* (DCs vs workstations vs web servers), so a busy DC isn't
	// flagged against quiet laptops and vice-versa.
	a.analyzePeerGroupBaseline(entityTotals)

	a.logger.Info("ueba: analysis complete",
		zap.Int("entities", len(stats)),
		zap.Duration("elapsed", time.Since(start)),
	)
}

// ── Per-entity baseline ─────────────────────────────────────────────────────

// analyzePerEntityBaseline builds, for each agent, a baseline of its own daily
// alert rate over the trailing window and flags today's volume when it exceeds
// the host's own mean + 2σ. This is a self-comparison (vs the host's history),
// complementing the peer-comparison spike detection in analyze(). It also
// finally writes a *correct* per-entity baseline into ueba_baselines (the
// legacy path stored the global average under every entity).
func (a *Analyzer) analyzePerEntityBaseline() {
	buckets, err := a.store.AlertDailyCountsPerEntity(a.entityBaselineDays)
	if err != nil {
		a.logger.Warn("ueba: per-entity baseline query failed", zap.Error(err))
		return
	}
	days := lastNDayKeys(a.entityBaselineDays) // oldest .. today (UTC)
	for agentID, byDay := range buckets {
		series := densify(byDay, days)

		// Persist the all-days per-entity baseline (informational summary).
		mean, std := meanStd(series[:len(series)-1])
		_ = a.store.UpsertUebaBaseline(&store.UebaBaseline{
			EntityID:    agentID,
			EntityType:  "agent",
			Metric:      "daily_alert_rate",
			AvgValue:    mean,
			StdDev:      std,
			SampleCount: len(series) - 1,
		})

		// Prefer a seasonal (same-weekday) baseline so a busy-Monday host isn't
		// judged against quiet weekends; fall back to the all-days baseline when
		// there isn't enough same-weekday history yet.
		z, fired, basis := spikeWithSeasonality(series, a.minSamples, a.spikeSigma)
		if !fired {
			continue
		}
		current := series[len(series)-1]
		a.insertAnomaly(&store.UebaAnomaly{
			EntityID:    agentID,
			EntityType:  "agent",
			AnomalyType: "entity_alert_spike",
			Description: fmt.Sprintf(
				"Per-entity alert spike: %.0f alerts today vs this host's own %s baseline (z=%.1f over %dd)",
				current, basis, z, a.entityBaselineDays),
			Severity: severityFromZScore(z),
			Score:    int(math.Min(50, z*10)),
		})
	}
}

// lastNDayKeys returns n UTC day keys (YYYY-MM-DD), oldest first, ending today.
func lastNDayKeys(n int) []string {
	now := time.Now().UTC()
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		// keys[n-1] = today, keys[0] = today-(n-1)
		keys[n-1-i] = now.AddDate(0, 0, -i).Format("2006-01-02")
	}
	return keys
}

// densify expands a sparse day→count map into a dense float series aligned to
// `days` (missing days = 0), so quiet days correctly pull the baseline down.
func densify(byDay map[string]int, days []string) []float64 {
	series := make([]float64, len(days))
	for i, d := range days {
		series[i] = float64(byDay[d])
	}
	return series
}

// entitySpike evaluates a per-entity daily series (oldest..today). It returns
// today's z-score against the baseline of the prior days, and whether it
// crosses the spike threshold. fired is false on cold start (too few baseline
// days) or zero variance — so a brand-new or perfectly-flat host never alerts.
func entitySpike(series []float64, minSamples int, sigma float64) (z float64, fired bool) {
	if len(series) < minSamples+1 {
		return 0, false
	}
	current := series[len(series)-1]
	mean, std := meanStd(series[:len(series)-1])
	if std <= 0 {
		return 0, false
	}
	z = (current - mean) / std
	return z, z >= sigma && current > mean
}

// sameWeekdaySamples returns the values on the same weekday as the last element
// (today), excluding today — indices len-8, len-15, … The series is assumed to
// be one-per-day, oldest..today, so stepping back by 7 lands on prior same
// weekdays.
func sameWeekdaySamples(series []float64) []float64 {
	var out []float64
	for i := len(series) - 1 - 7; i >= 0; i -= 7 {
		out = append(out, series[i])
	}
	return out
}

// spikeWithSeasonality flags today's count using a day-of-week-aware baseline
// when there's enough same-weekday history (basis "same-weekday"), otherwise
// falls back to the all-days self-baseline (basis "daily"). Returns the z-score,
// whether the spike threshold is crossed, and which basis was used.
func spikeWithSeasonality(series []float64, minSamples int, sigma float64) (z float64, fired bool, basis string) {
	samples := sameWeekdaySamples(series)
	if len(samples) >= minSamples {
		if mean, std := meanStd(samples); std > 0 {
			current := series[len(series)-1]
			z = (current - mean) / std
			return z, z >= sigma && current > mean, "same-weekday"
		}
	}
	z, fired = entitySpike(series, minSamples, sigma)
	return z, fired, "daily"
}

// ── Peer-group baseline ─────────────────────────────────────────────────────

// analyzePeerGroupBaseline flags a grouped host whose alert volume is a high
// outlier within its own role group (agents.group_id), using the 7d totals
// already computed in analyze(). Ungrouped hosts are skipped — they're covered
// by the fleet-wide spike check. Groups smaller than minSamples have no usable
// baseline and are skipped.
func (a *Analyzer) analyzePeerGroupBaseline(totals map[string]int) {
	groupOf, err := a.store.AgentGroupIDs()
	if err != nil {
		a.logger.Warn("ueba: peer-group lookup failed", zap.Error(err))
		return
	}

	cohorts := make(map[string][]float64) // group_id → member 7d totals
	for agentID, total := range totals {
		if g := groupOf[agentID]; g != "" {
			cohorts[g] = append(cohorts[g], float64(total))
		}
	}

	for agentID, total := range totals {
		g := groupOf[agentID]
		if g == "" {
			continue
		}
		cohort := cohorts[g]
		z, fired := peerGroupOutlier(float64(total), cohort, a.minSamples, a.spikeSigma)
		if !fired {
			continue
		}
		mean, std := meanStd(cohort)
		a.insertAnomaly(&store.UebaAnomaly{
			EntityID:    agentID,
			EntityType:  "agent",
			AnomalyType: "peer_group_spike",
			Description: fmt.Sprintf(
				"Peer-group outlier: %d alerts in %dd vs group %q baseline %.1f±%.1f/host (z=%.1f, %d peers)",
				total, baselineWindowDays, g, mean, std, z, len(cohort)),
			Severity: severityFromZScore(z),
			Score:    int(math.Min(50, z*10)),
		})
	}
}

// peerGroupOutlier reports whether `value` is a high outlier within its cohort
// (the cohort includes value itself, matching the fleet-wide check). Returns
// the z-score and whether it crosses the threshold. Cold start (cohort smaller
// than minSamples) or zero variance → not fired.
func peerGroupOutlier(value float64, cohort []float64, minSamples int, sigma float64) (z float64, fired bool) {
	if len(cohort) < minSamples {
		return 0, false
	}
	mean, std := meanStd(cohort)
	if std <= 0 {
		return 0, false
	}
	z = (value - mean) / std
	return z, z >= sigma && value > mean
}

// ── Login behavior ────────────────────────────────────────────────────────────

func (a *Analyzer) analyzeLoginBehavior(snap CollectorSnapshot) {
	for _, ls := range snap.Logins {
		// Off-hours logins: 23:00–06:00
		offHours := 0
		for h, cnt := range ls.UniqueHours {
			if h >= 23 || h < 6 {
				offHours += cnt
			}
		}
		if offHours > 0 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    ls.AgentID,
				EntityType:  "agent",
				AnomalyType: "off_hours_login",
				Description: fmt.Sprintf("%d login(s) detected outside business hours (23:00-06:00)", offHours),
				Severity:    "medium",
				Score:       int(math.Min(30, float64(offHours)*5)),
			})
		}

		// Failed login spike: > 10 failures in window
		if ls.FailedCount > 10 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    ls.AgentID,
				EntityType:  "agent",
				AnomalyType: "failed_login_spike",
				Description: fmt.Sprintf("%d failed login attempts detected (possible brute force)", ls.FailedCount),
				Severity:    "high",
				Score:       int(math.Min(45, float64(ls.FailedCount)*2)),
			})
		}

		// New source IP: flag any IP seen in the last hour that wasn't seen earlier in the window
		now := snap.CapturedAt
		recentCutoff := now.Add(-1 * time.Hour)
		recentIPs := make(map[string]bool)
		for _, e := range ls.Entries {
			if e.ts.After(recentCutoff) && !e.failed && e.sourceIP != "" {
				recentIPs[e.sourceIP] = true
			}
		}
		olderIPs := make(map[string]bool)
		for _, e := range ls.Entries {
			if e.ts.Before(recentCutoff) && e.sourceIP != "" {
				olderIPs[e.sourceIP] = true
			}
		}
		for ip := range recentIPs {
			if !olderIPs[ip] {
				a.insertAnomaly(&store.UebaAnomaly{
					EntityID:    ls.AgentID,
					EntityType:  "agent",
					AnomalyType: "new_source_ip",
					Description: fmt.Sprintf("Login from previously unseen source IP: %s", ip),
					Severity:    "high",
					Score:       25,
				})
			}
		}

		// Brute-force success chain: N failures from IP X within 1h, then a success from same IP X
		// This is a high-fidelity indicator of a successful credential attack.
		a.detectBruteForceSuccess(ls)
	}
}

// detectBruteForceSuccess checks whether any source IP had >= bruteForceFailThreshold
// failed login attempts within 1 hour followed by a successful login, indicating a
// credential brute-force that succeeded.
func (a *Analyzer) detectBruteForceSuccess(ls LoginSnapshot) {
	type ipStats struct {
		failures   int
		firstFail  time.Time
		lastFail   time.Time
		hadSuccess bool
	}
	stats := make(map[string]*ipStats)

	for _, e := range ls.Entries {
		if e.sourceIP == "" {
			continue
		}
		s := stats[e.sourceIP]
		if s == nil {
			s = &ipStats{}
			stats[e.sourceIP] = s
		}
		if e.failed {
			s.failures++
			if s.firstFail.IsZero() {
				s.firstFail = e.ts
			}
			s.lastFail = e.ts
		} else {
			// Only count as success if it happened after failures
			if s.failures >= a.bruteForceFailMin && e.ts.After(s.firstFail) {
				s.hadSuccess = true
			}
		}
	}

	for ip, s := range stats {
		if s.hadSuccess && s.failures >= a.bruteForceFailMin {
			// Confirm failures and success are within 1-hour window
			if s.lastFail.Sub(s.firstFail) <= time.Hour {
				a.insertAnomaly(&store.UebaAnomaly{
					EntityID:    ls.AgentID,
					EntityType:  "agent",
					AnomalyType: "brute_force_success",
					Description: fmt.Sprintf(
						"Brute-force attack succeeded: %d failed logins from %s followed by successful login",
						s.failures, ip,
					),
					Severity: "critical",
					Score:    50,
				})
			}
		}
	}
}

// ── Network behavior ──────────────────────────────────────────────────────────

func (a *Analyzer) analyzeNetworkBehavior(snap CollectorSnapshot) {
	for _, ns := range snap.Networks {
		uniqueCount := len(ns.UniqueDestIPs)
		if uniqueCount == 0 {
			continue
		}

		// Connection volume spike: flag if unique destinations > 50
		if uniqueCount > 50 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    ns.AgentID,
				EntityType:  "agent",
				AnomalyType: "connection_spike",
				Description: fmt.Sprintf("High unique destination count: %d unique IPs in 7d window", uniqueCount),
				Severity:    "medium",
				Score:       int(math.Min(25, float64(uniqueCount)/5)),
			})
		}

		// Data exfiltration signal: outbound bytes > threshold in last hour
		if ns.BytesOutLastHour >= a.exfilBytes {
			mb := ns.BytesOutLastHour / (1024 * 1024)
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    ns.AgentID,
				EntityType:  "agent",
				AnomalyType: "data_exfiltration",
				Description: fmt.Sprintf(
					"Unusually high outbound traffic: %d MB in the last hour (threshold: %d MB)",
					mb, a.exfilBytes/(1024*1024),
				),
				Severity: "high",
				Score:    int(math.Min(45, float64(mb)/10)),
			})
		}
	}
}

// ── Process behavior ──────────────────────────────────────────────────────────

func (a *Analyzer) analyzeProcessBehavior(snap CollectorSnapshot) {
	a.hashMu.Lock()
	defer a.hashMu.Unlock()

	for _, ps := range snap.Procs {
		// Ensure per-agent hash set exists
		if a.knownHashes[ps.AgentID] == nil {
			a.knownHashes[ps.AgentID] = make(map[string]bool)
		}
		known := a.knownHashes[ps.AgentID]

		// First-seen process hash: new sha256 not seen in any prior analysis cycle
		for _, entry := range ps.NewEntries {
			if entry.hash == "" {
				continue
			}
			if !known[entry.hash] {
				known[entry.hash] = true
				severity := "low"
				score := 10
				// Escalate if the process name is on the suspicious list
				if isSuspiciousProcess(entry.name) {
					severity = "high"
					score = 40
				}
				a.insertAnomaly(&store.UebaAnomaly{
					EntityID:    ps.AgentID,
					EntityType:  "agent",
					AnomalyType: "first_seen_process",
					Description: fmt.Sprintf(
						"First-seen executable: '%s' (sha256: %.12s...)", entry.name, entry.hash,
					),
					Severity: severity,
					Score:    score,
				})
			}
		}

		// Rare process: known suspicious names executed only once in 7d window
		for name, count := range ps.NameCounts {
			if count == 1 && isSuspiciousProcess(name) {
				a.insertAnomaly(&store.UebaAnomaly{
					EntityID:    ps.AgentID,
					EntityType:  "agent",
					AnomalyType: "rare_process",
					Description: fmt.Sprintf("Suspicious process: '%s' (seen only once in 7d baseline)", name),
					Severity:    "medium",
					Score:       20,
				})
			}
		}
	}
}

// isSuspiciousProcess returns true for process names that are high-risk when seen.
func isSuspiciousProcess(name string) bool {
	suspicious := map[string]bool{
		"mimikatz.exe": true, "meterpreter.exe": true,
		"nc.exe": true, "ncat.exe": true, "nmap.exe": true,
		"psexec.exe": true, "psexec64.exe": true,
		"wce.exe": true, "fgdump.exe": true,
		"procdump.exe": true, "cobaltstrike.exe": true,
		"metasploit.exe": true, "wmiexec.py": true,
		"rubeus.exe": true, "sharpkatz.exe": true,
		"certutil.exe": true, "bitsadmin.exe": true,
	}
	return suspicious[name]
}

// ── User behavior ─────────────────────────────────────────────────────────────

func (a *Analyzer) analyzeUserBehavior(snap CollectorSnapshot) {
	for _, us := range snap.Users {
		if us.Username == "" || us.Username == "-" || us.Username == "SYSTEM" {
			continue
		}

		// Multiple failed logins across agents
		if us.Failures > 5 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    us.Username,
				EntityType:  "user",
				AnomalyType: "user_multiple_failures",
				Description: fmt.Sprintf("User '%s' had %d failed login attempts across %d machine(s)",
					us.Username, us.Failures, len(us.AgentIDs)),
				Severity: "high",
				Score:    int(math.Min(40, float64(us.Failures)*4)),
			})
		}

		// User seen on multiple machines (lateral movement indicator)
		if len(us.AgentIDs) > 3 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    us.Username,
				EntityType:  "user",
				AnomalyType: "user_new_machine",
				Description: fmt.Sprintf("User '%s' logged into %d different machines in 7d",
					us.Username, len(us.AgentIDs)),
				Severity: "medium",
				Score:    int(math.Min(30, float64(len(us.AgentIDs))*5)),
			})
		}

		// Off-hours login for user
		offHours := 0
		for h, cnt := range us.Hours {
			if h >= 23 || h < 6 {
				offHours += cnt
			}
		}
		if offHours > 0 {
			a.insertAnomaly(&store.UebaAnomaly{
				EntityID:    us.Username,
				EntityType:  "user",
				AnomalyType: "off_hours_login",
				Description: fmt.Sprintf("User '%s' had %d login(s) outside business hours", us.Username, offHours),
				Severity:    "medium",
				Score:       int(math.Min(25, float64(offHours)*5)),
			})
		}

		// Upsert user risk score
		riskScore := computeUserRiskScore(us)
		rs := &store.UebaRiskScore{
			EntityID:   us.Username,
			EntityType: "user",
			RiskScore:  riskScore,
			RiskLevel:  riskLevelFromScore(riskScore),
		}
		_ = a.store.UpsertUebaRiskScore(rs)
	}
}

func computeUserRiskScore(us UserSnapshot) int {
	score := 0
	score += int(math.Min(30, float64(us.Failures)*5))
	score += int(math.Min(20, float64(len(us.AgentIDs))*5))
	return int(math.Min(100, float64(score)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// insertAnomaly emits a first-class alert for the anomaly (when an emitter is
// wired), back-links the resulting alert ID, then persists the anomaly row.
// Returns an error if persistence fails so callers can gate counters on it.
func (a *Analyzer) insertAnomaly(anomaly *store.UebaAnomaly) error {
	anomaly.DetectedAt = time.Now().UnixMilli()
	// Emit first so we can record the alert ID on the anomaly row, completing
	// the ueba_anomalies.alert_id back-link the schema already reserves.
	a.emitAlertForAnomaly(anomaly)
	if _, err := a.store.InsertUebaAnomaly(anomaly); err != nil {
		a.logger.Warn("ueba: failed to insert anomaly",
			zap.String("type", anomaly.AnomalyType),
			zap.Error(err),
		)
		return err
	}
	return nil
}

// emitAlertForAnomaly turns a UEBA anomaly into an alert and pushes it through
// the engine's pipeline. On success it sets anomaly.AlertID so the persisted
// anomaly links back to its alert. No-op when no emitter is wired.
func (a *Analyzer) emitAlertForAnomaly(anomaly *store.UebaAnomaly) {
	if a.emitter == nil {
		return
	}
	// Only agent-typed entities map cleanly onto RBA's agent risk model; user
	// entities still produce a visible alert but carry no AgentID.
	agentID := ""
	if anomaly.EntityType == "agent" {
		agentID = anomaly.EntityID
	}
	now := time.Now().UnixMilli()
	alert := &models.Alert{
		RuleID:      anomalyRuleID(anomaly.AnomalyType),
		Level:       levelFromSeverity(anomaly.Severity),
		AgentID:     agentID,
		Timestamp:   now,
		Title:       "UEBA: " + humanizeAnomaly(anomaly.AnomalyType),
		Description: anomaly.Description,
		RuleGroups:  []string{"ueba", "anomaly", anomaly.AnomalyType},
	}
	ev := &models.Event{
		Timestamp: now,
		Type:      "ueba.anomaly",
		AgentID:   agentID,
		Fields: map[string]interface{}{
			"entity_id":    anomaly.EntityID,
			"entity_type":  anomaly.EntityType,
			"anomaly_type": anomaly.AnomalyType,
			"score":        anomaly.Score,
		},
	}
	a.emitter.EmitAlert(ev, alert)
	if alert.ID != 0 {
		anomaly.AlertID = alert.ID
	}
}

// anomalyRuleID maps each anomaly type to a stable synthetic rule ID in a
// reserved 92xxx block, so UEBA alerts are filterable in the dashboard and
// individually weightable in RBA. Unknown types share a generic fallback.
func anomalyRuleID(anomalyType string) int {
	switch anomalyType {
	case "alert_spike":
		return 92001
	case "critical_alert_burst":
		return 92002
	case "entity_alert_spike":
		return 92003
	case "peer_group_spike":
		return 92004
	case "off_hours_login":
		return 92010
	case "failed_login_spike":
		return 92011
	case "new_source_ip":
		return 92012
	case "brute_force_success":
		return 92013
	case "connection_spike":
		return 92020
	case "data_exfiltration":
		return 92021
	case "first_seen_process":
		return 92030
	case "rare_process":
		return 92031
	case "user_multiple_failures":
		return 92040
	case "user_new_machine":
		return 92041
	default:
		return 92000
	}
}

// levelFromSeverity maps the anomaly severity string to the numeric alert level
// RBA uses for risk weighting when no per-rule weight is configured.
func levelFromSeverity(sev string) int {
	switch sev {
	case "critical":
		return 13
	case "high":
		return 10
	case "medium":
		return 7
	default:
		return 4
	}
}

// humanizeAnomaly turns a snake_case anomaly type into a Title Case label.
func humanizeAnomaly(anomalyType string) string {
	out := make([]rune, 0, len(anomalyType))
	upper := true
	for _, r := range anomalyType {
		if r == '_' {
			out = append(out, ' ')
			upper = true
			continue
		}
		if upper && r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		upper = false
		out = append(out, r)
	}
	return string(out)
}

func meanStd(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	avg := sum / float64(len(vals))
	if len(vals) == 1 {
		return avg, 0
	}
	var variance float64
	for _, v := range vals {
		diff := v - avg
		variance += diff * diff
	}
	return avg, math.Sqrt(variance / float64(len(vals)))
}

func computeRiskScore(total, critCount, maxLevel, anomalies int) int {
	score := 0
	score += int(math.Min(30, float64(total)*0.5))
	score += int(math.Min(40, float64(critCount)*8))
	score += int(math.Min(15, float64(maxLevel)))
	score += int(math.Min(15, float64(anomalies)*5))
	return int(math.Min(100, float64(score)))
}

func riskLevelFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func severityFromZScore(z float64) string {
	switch {
	case z >= 4:
		return "critical"
	case z >= 3:
		return "high"
	case z >= 2:
		return "medium"
	default:
		return "low"
	}
}
