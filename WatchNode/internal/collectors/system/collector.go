package system

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

const CollectorName = "system"

// Collector collects system metrics (CPU, memory, disk, network, processes).
type Collector struct {
	cfg     agent.SystemCollectorConfig
	interval time.Duration
	dataCh  chan models.DataPoint
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New creates a system metrics collector.
func New(cfg agent.SystemCollectorConfig) *Collector {
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
	metrics := make(map[string]bool)
	for _, m := range c.cfg.Metrics {
		metrics[m] = true
	}

	if metrics["cpu"] {
		if percs, err := cpu.Percent(0, true); err == nil {
			for i, p := range percs {
				c.emit(ts, "system.cpu", map[string]interface{}{
					"core":   i,
					"percent": p,
				}, nil)
			}
		}
		if percs, err := cpu.Percent(0, false); err == nil && len(percs) > 0 {
			c.emit(ts, "system.cpu.total", map[string]interface{}{"percent": percs[0]}, nil)
		}
	}
	if metrics["load"] || metrics["cpu"] {
		if avg, err := load.Avg(); err == nil {
			c.emit(ts, "system.load", map[string]interface{}{
				"load1":  avg.Load1,
				"load5":  avg.Load5,
				"load15": avg.Load15,
			}, nil)
		}
	}

	if metrics["memory"] {
		if v, err := mem.VirtualMemory(); err == nil {
			c.emit(ts, "system.memory", map[string]interface{}{
				"total":  v.Total,
				"used":   v.Used,
				"free":   v.Free,
				"cached": v.Cached,
				"percent": v.UsedPercent,
			}, nil)
		}
	}

	if metrics["disk"] {
		if parts, err := disk.Partitions(false); err == nil {
			for _, p := range parts {
				if usage, err := disk.Usage(p.Mountpoint); err == nil {
					c.emit(ts, "system.disk", map[string]interface{}{
						"mount":   p.Mountpoint,
						"total":   usage.Total,
						"used":    usage.Used,
						"free":    usage.Free,
						"percent": usage.UsedPercent,
					}, map[string]string{"mount": p.Mountpoint})
				}
			}
		}
	}

	if metrics["network"] {
		if counters, err := net.IOCounters(false); err == nil && len(counters) > 0 {
			n := counters[0]
			c.emit(ts, "system.network", map[string]interface{}{
				"bytes_sent":   n.BytesSent,
				"bytes_recv":   n.BytesRecv,
				"packets_sent": n.PacketsSent,
				"packets_recv": n.PacketsRecv,
				"errin":        n.Errin,
				"errout":       n.Errout,
			}, nil)
		}
	}

	if metrics["processes"] {
		if procs, err := process.Processes(); err == nil {
			for _, p := range procs {
				name, _ := p.Name()
				cmdline, _ := p.Cmdline()
				cpuPct, _ := p.CPUPercent()
				memPct, _ := p.MemoryPercent()
				c.emit(ts, "system.process", map[string]interface{}{
					"pid":     p.Pid,
					"name":    name,
					"cmdline": cmdline,
					"cpu_percent": cpuPct,
					"memory_percent": memPct,
				}, map[string]string{"pid": strconv.Itoa(int(p.Pid))})
			}
		}
	}

	if info, err := host.Info(); err == nil {
		c.emit(ts, "system.host", map[string]interface{}{
			"uptime":   info.Uptime,
			"boot_time": info.BootTime,
			"hostname": info.Hostname,
			"os":       info.OS,
			"platform": info.Platform,
		}, nil)
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
