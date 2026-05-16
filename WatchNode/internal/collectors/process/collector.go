package process

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/internal/utils"
	"github.com/shirou/gopsutil/v3/process"
)

const CollectorName = "process"

// Collector monitors process creation and parent-child relationships.
type Collector struct {
	cfg      agent.ProcessCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	seenPIDs map[int32]struct{}
	mu       sync.Mutex
}

// New creates a process monitoring collector.
func New(cfg agent.ProcessCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 30*time.Second)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 128),
		stopCh:   make(chan struct{}),
		seenPIDs: make(map[int32]struct{}),
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
	procs, err := process.Processes()
	if err != nil {
		return
	}
	ts := time.Now()
	c.mu.Lock()
	newPIDs := make(map[int32]struct{})
	for _, p := range procs {
		newPIDs[p.Pid] = struct{}{}
		if _, seen := c.seenPIDs[p.Pid]; seen {
			continue
		}
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()
		ppid, _ := p.Ppid()
		createTime, _ := p.CreateTime()
		exe, _ := p.Exe()
		fields := map[string]interface{}{
			"pid":         p.Pid,
			"ppid":        ppid,
			"name":        name,
			"cmdline":     cmdline,
			"create_time": createTime,
			"exe":         exe,
		}
		if exe != "" {
			if info, err := os.Stat(exe); err == nil && info.Size() < 10*1024*1024 {
				if hash, err := utils.SHA256File(exe); err == nil {
					fields["sha256"] = hash
				}
			}
		}
		c.emit(ts, "process.new", fields, nil)
	}
	for pid := range c.seenPIDs {
		if _, stillRunning := newPIDs[pid]; !stillRunning {
			c.emit(ts, "process.terminated", map[string]interface{}{
				"pid": pid,
			}, nil)
		}
	}
	c.seenPIDs = newPIDs
	c.mu.Unlock()
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
