// Package yarascan scans the memory of running processes with YARA, catching
// fileless / injected / packed malware that on-disk scanning misses.
//
// It shells out to the `yara` binary (so the agent keeps its CGO-free static
// build) — `yara <rules> <pid>` scans a process and prints one "<rule> <pid>"
// line per match. The binary must be present on the endpoint; if it isn't, the
// collector quietly stays idle. Matches are emitted as "yara.match" events that
// the WatchTower rule engine turns into alerts (rule 19580, MITRE T1620).
package yarascan

import (
	"bufio"
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

//go:embed default_rules.yar
var defaultRules []byte

const CollectorName = "yara_memory"

type Collector struct {
	cfg       agent.YaraCollectorConfig
	interval  time.Duration
	dataCh    chan models.DataPoint
	stopCh    chan struct{}
	wg        sync.WaitGroup
	yaraBin   string
	rulesPath string
	ready     bool
}

func New(cfg agent.YaraCollectorConfig) *Collector {
	return &Collector{
		cfg:      cfg,
		interval: agent.ParseDuration(cfg.Interval, 10*time.Minute),
		dataCh:   make(chan models.DataPoint, 64),
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Name() string                      { return CollectorName }
func (c *Collector) Interval() time.Duration           { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
	bin := c.cfg.YaraPath
	if bin == "" {
		bin = "yara"
		if runtime.GOOS == "windows" {
			bin = "yara64.exe"
		}
	}
	// Quietly stay idle if yara isn't installed/bundled — never fail the agent.
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil
	}
	c.yaraBin = path

	rp := c.cfg.RulesFile
	if rp == "" {
		rp = filepath.Join(os.TempDir(), "sentinel_yara_rules.yar")
		if werr := os.WriteFile(rp, defaultRules, 0o600); werr != nil {
			return nil
		}
	}
	c.rulesPath = rp
	c.ready = true

	c.wg.Add(1)
	go c.loop(ctx)
	return nil
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

func (c *Collector) loop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.scanAll(ctx) // initial sweep
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-t.C:
			c.scanAll(ctx)
		}
	}
}

func (c *Collector) scanAll(ctx context.Context) {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	self := int32(os.Getpid())
	timeout := time.Duration(c.cfg.ScanTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	scanned := 0
	for _, p := range procs {
		if p.Pid == self || p.Pid <= 0 {
			continue
		}
		if c.cfg.MaxProcs > 0 && scanned >= c.cfg.MaxProcs {
			return
		}
		select {
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		name, _ := p.Name()
		c.scanPID(ctx, p.Pid, name, timeout)
		scanned++
	}
}

func (c *Collector) scanPID(ctx context.Context, pid int32, name string, timeout time.Duration) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Non-zero exit just means yara couldn't scan (no perms, gone) or matched
	// nothing useful — either way we only care about printed match lines.
	out, _ := exec.CommandContext(cctx, c.yaraBin, c.rulesPath, strconv.Itoa(int(pid))).Output()
	if len(out) == 0 {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) == 0 {
			continue
		}
		c.emit(fields[0], pid, name) // "<rulename> <pid>"
	}
}

func (c *Collector) emit(rule string, pid int32, name string) {
	select {
	case c.dataCh <- models.DataPoint{
		Timestamp: time.Now(),
		Type:      "yara.match",
		Fields: map[string]interface{}{
			"yara_rule":    rule,
			"pid":          int(pid),
			"process_name": name,
			"message":      "YARA rule " + rule + " matched in memory of process " + name,
		},
		Tags: map[string]string{
			"category": "malware",
			"severity": "critical",
		},
	}:
	default:
	}
}
