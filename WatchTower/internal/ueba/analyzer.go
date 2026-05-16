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
	"time"

	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

const (
	baselineWindowDays  = 7
	analyzeInterval     = time.Hour
	spikeThresholdSigma = 2.0
	minSamplesForSpike  = 3
)

// Analyzer periodically computes UEBA baselines, detects anomalies, and
// updates entity risk scores.
type Analyzer struct {
	store     *store.Store
	logger    *zap.Logger
	collector *EventCollector // may be nil if not wired
}

func NewAnalyzer(st *store.Store, logger *zap.Logger, collector *EventCollector) *Analyzer {
	return &Analyzer{store: st, logger: logger, collector: collector}
}

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

	for _, s := range stats {
		agentID := s["agent_id"].(string)
		total := s["total"].(int)
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
		if len(stats) >= minSamplesForSpike && globalStd > 0 {
			zScore := (float64(total) - globalAvg) / globalStd
			if zScore >= spikeThresholdSigma {
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
				if _, err := a.store.InsertUebaAnomaly(anomaly); err == nil {
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
			if _, err := a.store.InsertUebaAnomaly(anomaly); err == nil {
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

	a.logger.Info("ueba: analysis complete",
		zap.Int("entities", len(stats)),
		zap.Duration("elapsed", time.Since(start)),
	)
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

		// New source IP: only flag when there is exactly one IP and it hasn't been seen before
		// (baseline comparison — flag any IP seen in the last hour that's brand new)
		now := snap.CapturedAt
		recentCutoff := now.Add(-1 * time.Hour)
		recentIPs := make(map[string]bool)
		for _, e := range ls.Entries {
			if e.ts.After(recentCutoff) && !e.failed && e.sourceIP != "" {
				recentIPs[e.sourceIP] = true
			}
		}
		// Count IPs seen only in the last hour vs those seen earlier
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
	}
}

// ── Network behavior ──────────────────────────────────────────────────────────

func (a *Analyzer) analyzeNetworkBehavior(snap CollectorSnapshot) {
	for _, ns := range snap.Networks {
		uniqueCount := len(ns.UniqueDestIPs)
		if uniqueCount == 0 {
			continue
		}

		// Connection volume spike: flag if unique destinations > 50 (configurable threshold)
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
	}
}

// ── Process behavior ──────────────────────────────────────────────────────────

func (a *Analyzer) analyzeProcessBehavior(snap CollectorSnapshot) {
	for _, ps := range snap.Procs {
		// Rare process: executed only once in the 7-day window
		for name, count := range ps.NameCounts {
			if count == 1 && isRareProcess(name) {
				a.insertAnomaly(&store.UebaAnomaly{
					EntityID:    ps.AgentID,
					EntityType:  "agent",
					AnomalyType: "rare_process",
					Description: fmt.Sprintf("Rare process execution: '%s' (seen only once in 7d baseline)", name),
					Severity:    "low",
					Score:       10,
				})
			}
		}
	}
}

// isRareProcess returns true for process names that are suspicious when rarely seen.
func isRareProcess(name string) bool {
	suspicious := map[string]bool{
		"mimikatz.exe": true, "meterpreter.exe": true,
		"nc.exe": true, "ncat.exe": true, "nmap.exe": true,
		"psexec.exe": true, "psexec64.exe": true,
		"wce.exe": true, "fgdump.exe": true,
		"reg.exe": true, "regsvr32.exe": true,
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

func (a *Analyzer) insertAnomaly(anomaly *store.UebaAnomaly) {
	anomaly.DetectedAt = time.Now().UnixMilli()
	if _, err := a.store.InsertUebaAnomaly(anomaly); err != nil {
		a.logger.Warn("ueba: failed to insert anomaly",
			zap.String("type", anomaly.AnomalyType),
			zap.Error(err),
		)
	}
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
