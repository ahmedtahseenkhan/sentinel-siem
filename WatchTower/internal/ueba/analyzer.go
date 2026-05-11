// Package ueba implements User and Entity Behavior Analytics for Sentinel SIEM.
// It runs statistical baseline computation on the PostgreSQL alerts table,
// detects anomalies when current activity deviates significantly from the
// historical norm, and maintains rolling risk scores for every agent and user.
//
// Anomaly detection uses the 2-sigma rule:
//   anomaly when: current_value > baseline_avg + 2 * baseline_std_dev
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
	baselineWindowDays = 7  // rolling window for baseline computation
	analyzeInterval    = time.Hour
	spikeThresholdSigma = 2.0 // flag when value exceeds avg + 2σ
	minSamplesForSpike  = 3   // need at least 3 samples before flagging
)

// Analyzer periodically computes UEBA baselines, detects anomalies, and
// updates entity risk scores.
type Analyzer struct {
	store  *store.Store
	logger *zap.Logger
}

func NewAnalyzer(st *store.Store, logger *zap.Logger) *Analyzer {
	return &Analyzer{store: st, logger: logger}
}

// Start runs the analyze loop until ctx is cancelled.
func (a *Analyzer) Start(ctx context.Context) {
	// Run immediately on startup, then hourly.
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

	stats, err := a.store.AlertStatsPerEntity(baselineWindowDays)
	if err != nil {
		a.logger.Error("ueba: failed to fetch alert stats", zap.Error(err))
		return
	}

	if len(stats) == 0 {
		a.logger.Debug("ueba: no alert data yet — skipping")
		return
	}

	// Compute aggregate values across all entities for cross-entity baseline.
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

		// Update or create baseline for this entity.
		baseline := &store.UebaBaseline{
			EntityID:    agentID,
			EntityType:  "agent",
			Metric:      "alert_rate_7d",
			AvgValue:    globalAvg,
			StdDev:      globalStd,
			SampleCount: len(stats),
		}
		_ = a.store.UpsertUebaBaseline(baseline)

		// Anomaly detection: alert spike (entity has significantly more alerts than peers).
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

		// Anomaly: sustained critical alerts.
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

		// Compute risk score.
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

	a.logger.Info("ueba: analysis complete",
		zap.Int("entities", len(stats)),
		zap.Duration("elapsed", time.Since(start)),
	)
}

// ── Statistical helpers ───────────────────────────────────────────────────────

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
	score += int(math.Min(30, float64(total)*0.5))    // up to 30 from total alerts
	score += int(math.Min(40, float64(critCount)*8))  // up to 40 from critical alerts
	score += int(math.Min(15, float64(maxLevel)))     // up to 15 from max level
	score += int(math.Min(15, float64(anomalies)*5))  // up to 15 from anomalies
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
