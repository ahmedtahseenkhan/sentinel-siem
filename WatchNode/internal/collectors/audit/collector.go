// Package audit collects Linux auditd events.
//
// It opens /var/log/audit/audit.log, tails new lines (with rotation handling),
// groups multi-line records by msg ID, parses key=value pairs (including
// hex-encoded values like name=2F65... for paths containing spaces), and:
//
//  1. Emits each grouped record as a structured "log.audit" DataPoint.
//  2. For records that include a file path (type=PATH) and a subject (auid
//     or uid), pushes a whodata.Entry into the shared cache so the FIM
//     collector can enrich its emit with who-changed-what attribution.
//
// On non-Linux platforms the collector is a no-op (see collector_other.go).
package audit

import (
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "audit"

// Collector tails the Linux audit log.
type Collector struct {
	cfg      agent.AuditCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New returns a new audit collector. cfg.Path defaults to /var/log/audit/audit.log.
func New(cfg agent.AuditCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 1*time.Second)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 512),
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }
func (c *Collector) Stop() error                      { close(c.stopCh); c.wg.Wait(); return nil }

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
