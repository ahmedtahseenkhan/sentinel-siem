package network

import (
	"context"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/shirou/gopsutil/v3/net"
)

const CollectorName = "network"

// Collector monitors active network connections and listening ports.
type Collector struct {
	cfg      agent.NetworkCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
}

// New creates a network connections collector.
func New(cfg agent.NetworkCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 30*time.Second)
	return &Collector{
		cfg:     cfg,
		interval: interval,
		dataCh:  make(chan models.DataPoint, 64),
		stopCh:  make(chan struct{}),
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
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.collect()
		}
	}
}

// Stop implements models.Collector.
func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) collect() {
	ts := time.Now()
	conns, err := net.Connections("all")
	if err != nil {
		return
	}
	for _, conn := range conns {
		c.emit(ts, "network.connection", map[string]interface{}{
			"family":   conn.Family,
			"type":     conn.Type,
			"laddr":    conn.Laddr.IP,
			"lport":    conn.Laddr.Port,
			"raddr":    conn.Raddr.IP,
			"rport":    conn.Raddr.Port,
			"status":   conn.Status,
			"pid":      conn.Pid,
		}, map[string]string{"status": conn.Status})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
