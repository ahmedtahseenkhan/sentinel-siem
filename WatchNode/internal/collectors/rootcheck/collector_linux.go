//go:build linux

package rootcheck

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const suidBaselinePath = "/var/lib/watchnode/rootcheck-suid-baseline"

func (c *Collector) Start(ctx context.Context) error {
	c.loadSUIDBaseline()
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
	c.emit(ts, "rootcheck.scan_complete", map[string]interface{}{
		"timestamp": ts.Unix(),
	}, nil)
}

// checkHiddenProcesses compares /proc PIDs against ps output. To avoid the
// race window between the two reads (every short-lived process exiting in
// between would falsely look "hidden"), we re-check each suspect PID after
// a short delay before emitting.
func (c *Collector) checkHiddenProcesses(ts time.Time) {
	procPIDs := readProcPIDs()
	psPIDs := readPsPIDs()
	if procPIDs == nil || psPIDs == nil {
		return
	}

	var suspects []string
	for pid := range procPIDs {
		if !psPIDs[pid] {
			suspects = append(suspects, pid)
		}
	}
	if len(suspects) == 0 {
		return
	}

	// Recheck after a short delay; only alert if STILL hidden.
	time.Sleep(200 * time.Millisecond)
	procPIDs2 := readProcPIDs()
	psPIDs2 := readPsPIDs()
	for _, pid := range suspects {
		if procPIDs2[pid] && !psPIDs2[pid] {
			c.emit(ts, "rootcheck.hidden_process", map[string]interface{}{
				"pid":     pid,
				"message": fmt.Sprintf("Process %s in /proc but not in ps after recheck", pid),
			}, map[string]string{"pid": pid})
		}
	}
}

func readProcPIDs() map[string]bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() && isNumeric(e.Name()) {
			out[e.Name()] = true
		}
	}
	return out
}

func readPsPIDs() map[string]bool {
	out, err := exec.Command("ps", "-eo", "pid").Output()
	if err != nil {
		return nil
	}
	pids := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		pid := strings.TrimSpace(sc.Text())
		if isNumeric(pid) {
			pids[pid] = true
		}
	}
	return pids
}

// checkHiddenPorts compares /proc/net/tcp LISTEN entries (state column 0x0A)
// against ss -tln output. Filtering by LISTEN is essential: the original
// implementation compared ALL connection states, so every CLOSE_WAIT /
// TIME_WAIT socket alerted as "hidden", flooding the console.
func (c *Collector) checkHiddenPorts(ts time.Time) {
	procPorts := readProcNetListenPorts("/proc/net/tcp")
	procPorts = append(procPorts, readProcNetListenPorts("/proc/net/tcp6")...)

	out, err := exec.Command("ss", "-tln").Output()
	if err != nil {
		return
	}
	ssPorts := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// ss prints Local Address:Port — for v6 this can be "[::]:80" or
		// "*:80". Take the substring after the last colon.
		laddr := fields[3]
		if idx := strings.LastIndexByte(laddr, ':'); idx >= 0 {
			ssPorts[laddr[idx+1:]] = true
		}
	}

	for _, port := range procPorts {
		if !ssPorts[port] {
			c.emit(ts, "rootcheck.hidden_port", map[string]interface{}{
				"port":    port,
				"message": fmt.Sprintf("Port %s LISTENing in /proc/net but not in ss", port),
			}, map[string]string{"port": port})
		}
	}
}

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

// checkSUIDFiles scans configured dirs and alerts only on SUID/SGID files
// that did NOT exist in the previous baseline. The first scan after agent
// install establishes the baseline silently; subsequent scans alert on
// additions only — matching Wazuh's behavior and making the signal usable.
func (c *Collector) checkSUIDFiles(ts time.Time) {
	current := map[string]struct{}{}
	for _, dir := range c.cfg.ScanDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
				return nil
			}
			current[path] = struct{}{}
			c.suidBaselineMu.Lock()
			_, known := c.suidBaseline[path]
			c.suidBaselineMu.Unlock()
			if known {
				return nil
			}
			// New SUID/SGID file — alert.
			c.emit(ts, "rootcheck.suid_file_new", map[string]interface{}{
				"path":     path,
				"mode":     fmt.Sprintf("%o", mode.Perm()),
				"is_suid":  mode&os.ModeSetuid != 0,
				"is_sgid":  mode&os.ModeSetgid != 0,
				"size":     info.Size(),
				"mod_time": info.ModTime().Unix(),
				"message":  fmt.Sprintf("New SUID/SGID file: %s", path),
			}, map[string]string{"path": path})
			return nil
		})
	}

	// Promote current to baseline and persist.
	c.suidBaselineMu.Lock()
	c.suidBaseline = current
	c.suidBaselineMu.Unlock()
	c.saveSUIDBaseline(current)
}

func (c *Collector) loadSUIDBaseline() {
	data, err := os.ReadFile(suidBaselinePath)
	c.suidBaselineMu.Lock()
	defer c.suidBaselineMu.Unlock()
	c.suidBaseline = map[string]struct{}{}
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.TrimSpace(line)
		if p != "" {
			c.suidBaseline[p] = struct{}{}
		}
	}
}

func (c *Collector) saveSUIDBaseline(set map[string]struct{}) {
	_ = os.MkdirAll(filepath.Dir(suidBaselinePath), 0o755)
	var b strings.Builder
	for p := range set {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(suidBaselinePath, []byte(b.String()), 0o644)
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// readProcNetListenPorts parses /proc/net/tcp{,6} and returns only ports
// in LISTEN state (st column = 0x0A). The original code returned every
// state, causing massive false-positive hidden-port alerts.
func readProcNetListenPorts(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ports []string
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		// fields: sl local_addr rem_addr st ...
		if !strings.EqualFold(fields[3], "0A") {
			continue
		}
		laddr := fields[1] // "0100007F:1F90"
		parts := strings.Split(laddr, ":")
		if len(parts) == 2 {
			if p := hexToDecimal(parts[1]); p != "" {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func hexToDecimal(h string) string {
	var n int
	for _, c := range h {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'A' && c <= 'F':
			n += int(c-'A') + 10
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		default:
			return ""
		}
	}
	return fmt.Sprintf("%d", n)
}
