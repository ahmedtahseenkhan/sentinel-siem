package sca

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "sca"

// Collector runs Security Configuration Assessment scans using loaded policies.
type Collector struct {
	cfg      agent.SCACollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates an SCA collector.
func New(cfg agent.SCACollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 12*time.Hour)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 256),
		stopCh:   make(chan struct{}),
	}
}

// Name implements models.Collector.
func (c *Collector) Name() string { return CollectorName }

// Interval implements models.Collector.
func (c *Collector) Interval() time.Duration { return c.interval }

// DataChan implements models.Collector.
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

// Start implements models.Collector.
func (c *Collector) Start(ctx context.Context) error {
	// Run initial scan
	c.runScan()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.runScan()
		}
	}
}

func (c *Collector) runScan() {
	policies, err := LoadPolicies(c.cfg.PolicyDirs)
	if err != nil || len(policies) == 0 {
		return
	}

	ts := time.Now()
	for _, policy := range policies {
		results := EvaluatePolicy(policy)
		summary := Summarize(policy, results)

		// Emit summary event
		summaryJSON, _ := json.Marshal(summary)
		c.emit(ts, "sca.summary", map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"summary":     string(summaryJSON),
			"total":       summary.Total,
			"passed":      summary.Passed,
			"failed":      summary.Failed,
			"score":       summary.Score,
		}, map[string]string{"policy_id": policy.ID})

		// Emit individual check results
		for _, r := range results {
			c.emit(ts, "sca.result", map[string]interface{}{
				"policy_id":   policy.ID,
				"check_id":    r.CheckID,
				"title":       r.Title,
				"description": r.Description,
				"rationale":   r.Rationale,
				"remediation": r.Remediation,
				"compliance":  r.Compliance,
				"result":      r.Result,
				"reason":      r.Reason,
			}, map[string]string{"policy_id": policy.ID, "result": r.Result})
		}
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// Stop implements models.Collector.
func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}
