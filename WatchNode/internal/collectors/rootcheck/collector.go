// Package rootcheck performs rootkit and host-anomaly detection.
//
// This file is the cross-platform shell (constructor, channels, scheduling).
// All actual scans live in collector_linux.go because they depend on
// /proc, /proc/net/tcp, and the ss / ps binaries. On non-Linux platforms
// the Start method is a no-op (see collector_other.go) — emitting a
// scan_complete event there would falsely advertise coverage we do not
// have.
package rootcheck

import (
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "rootcheck"

// knownRootkitFiles are paths commonly associated with rootkits.
// Kept short — production deployments should layer a proper signature feed
// (chkrootkit DB, OSSEC rootkit_files.txt) on top via the audit collector.
var knownRootkitFiles = []string{
	"/dev/.oz",
	"/dev/.rk",
	"/usr/lib/security/.config",
	"/usr/bin/.sniffer",
	"/dev/ptyr",
	"/usr/include/file.h",
	"/usr/include/proc.h",
	"/usr/include/addr.h",
	"/usr/bin/sourcemask",
	"/usr/bin/ct",
	"/etc/cron.d/core.cron",
	"/lib/security/.config",
	"/lib/libload.so",
	"/lib/libproc.a",
}

// Collector performs rootkit and anomaly detection scans.
type Collector struct {
	cfg      agent.RootcheckCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// suidBaseline holds the SUID file set from the previous successful scan.
	// Without it, every scan re-alerts on every legitimate SUID binary
	// (sudo, passwd, ping...) — a flood that hides real findings.
	suidBaselineMu sync.Mutex
	suidBaseline   map[string]struct{}
}

// New creates a rootcheck collector.
func New(cfg agent.RootcheckCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 12*time.Hour)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 256),
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
