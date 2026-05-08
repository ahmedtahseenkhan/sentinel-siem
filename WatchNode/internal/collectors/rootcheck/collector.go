package rootcheck

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "rootcheck"

// knownRootkitFiles are paths commonly associated with rootkits.
var knownRootkitFiles = []string{
	"/dev/.oz",
	"/dev/.rk",
	"/usr/lib/security/.config",
	"/usr/bin/.sniffer",
	"/tmp/.ICE-unix",
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

func (c *Collector) Name() string                         { return CollectorName }
func (c *Collector) Interval() time.Duration              { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint     { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
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

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) runScan() {
	ts := time.Now()
	if c.cfg.CheckHiddenProcs {
		c.checkHiddenProcesses(ts)
	}
	if c.cfg.CheckHiddenPorts {
		c.checkHiddenPorts(ts)
	}
	if c.cfg.CheckRootkitFiles {
		c.checkRootkitFiles(ts)
	}
	if c.cfg.CheckSUID {
		c.checkSUIDFiles(ts)
	}
	// Emit scan complete event
	c.emit(ts, "rootcheck.scan_complete", map[string]interface{}{
		"timestamp": ts.Unix(),
	}, nil)
}

// checkHiddenProcesses compares /proc entries against ps output to find hidden processes.
func (c *Collector) checkHiddenProcesses(ts time.Time) {
	procPIDs := make(map[string]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && isNumeric(e.Name()) {
			procPIDs[e.Name()] = true
		}
	}

	out, err := exec.Command("ps", "-eo", "pid").Output()
	if err != nil {
		return
	}
	psPIDs := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		pid := strings.TrimSpace(scanner.Text())
		if isNumeric(pid) {
			psPIDs[pid] = true
		}
	}

	// Processes in /proc but not in ps = potentially hidden
	for pid := range procPIDs {
		if !psPIDs[pid] {
			c.emit(ts, "rootcheck.hidden_process", map[string]interface{}{
				"pid":     pid,
				"message": fmt.Sprintf("Process %s found in /proc but not in ps output", pid),
			}, map[string]string{"pid": pid})
		}
	}
}

// checkHiddenPorts compares /proc/net against ss output.
func (c *Collector) checkHiddenPorts(ts time.Time) {
	procPorts := readProcNetPorts("/proc/net/tcp")
	procPorts = append(procPorts, readProcNetPorts("/proc/net/tcp6")...)

	out, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		return
	}
	ssPorts := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			parts := strings.Split(fields[3], ":")
			if len(parts) > 0 {
				ssPorts[parts[len(parts)-1]] = true
			}
		}
	}

	for _, port := range procPorts {
		if !ssPorts[port] {
			c.emit(ts, "rootcheck.hidden_port", map[string]interface{}{
				"port":    port,
				"message": fmt.Sprintf("Port %s found in /proc/net but not in ss output", port),
			}, map[string]string{"port": port})
		}
	}
}

// checkRootkitFiles checks for known rootkit file paths.
func (c *Collector) checkRootkitFiles(ts time.Time) {
	for _, path := range knownRootkitFiles {
		if _, err := os.Stat(path); err == nil {
			c.emit(ts, "rootcheck.rootkit_file", map[string]interface{}{
				"path":    path,
				"message": fmt.Sprintf("Known rootkit file detected: %s", path),
			}, map[string]string{"path": path})
		}
	}
}

// checkSUIDFiles scans directories for files with SUID/SGID bits set.
func (c *Collector) checkSUIDFiles(ts time.Time) {
	for _, dir := range c.cfg.ScanDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				c.emit(ts, "rootcheck.suid_file", map[string]interface{}{
					"path":     path,
					"mode":     fmt.Sprintf("%o", mode.Perm()),
					"is_suid":  mode&os.ModeSetuid != 0,
					"is_sgid":  mode&os.ModeSetgid != 0,
					"size":     info.Size(),
					"mod_time": info.ModTime().Unix(),
				}, map[string]string{"path": path})
			}
			return nil
		})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func readProcNetPorts(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ports []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 { // skip header
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) == 2 {
			port := hexToDecimal(parts[1])
			if port != "" {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

func hexToDecimal(hex string) string {
	var result int
	for _, c := range hex {
		result *= 16
		if c >= '0' && c <= '9' {
			result += int(c - '0')
		} else if c >= 'A' && c <= 'F' {
			result += int(c-'A') + 10
		} else if c >= 'a' && c <= 'f' {
			result += int(c-'a') + 10
		}
	}
	return fmt.Sprintf("%d", result)
}
