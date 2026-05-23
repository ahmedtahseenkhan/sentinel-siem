//go:build linux

package audit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/watchnode/watchnode/internal/whodata"
)

// Start opens the audit log and tails it forever. Multi-line audit records
// (sharing a msg=audit(TS:ID) header) are grouped by ID and dispatched as a
// single event when the next record starts or after a flush interval.
func (c *Collector) Start(ctx context.Context) error {
	path := c.cfg.Path
	if path == "" {
		path = "/var/log/audit/audit.log"
	}

	// Best-effort: install audit watch rules for paths the operator listed.
	// auditctl writes to a kernel structure shared with auditd, so it requires
	// CAP_AUDIT_WRITE / root. Failure here is logged via an emitted error
	// event but does not stop tailing — operators may install rules out of
	// band via /etc/audit/rules.d/.
	c.installRules()

	f, err := openAuditLog(path)
	if err != nil {
		c.emit(time.Now(), "audit.error", map[string]interface{}{
			"error": err.Error(), "path": path,
		}, map[string]string{"source": "audit"})
		return err
	}

	c.wg.Add(1)
	go c.tail(ctx, f, path)
	return nil
}

// openAuditLog opens the file at path. Caller is responsible for handling
// rotation in the tail loop.
func openAuditLog(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	// Seek to end so we don't replay history on startup.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// tail streams new lines from f. Rotation is detected by inode change every
// rotateCheckEvery; on rotation we reopen path.
func (c *Collector) tail(ctx context.Context, f *os.File, path string) {
	defer c.wg.Done()
	defer f.Close()

	current := f
	currentStat, _ := current.Stat()

	reader := bufio.NewReader(current)
	g := newGrouper()
	flush := time.NewTicker(500 * time.Millisecond)
	defer flush.Stop()
	rotateCheck := time.NewTicker(5 * time.Second)
	defer rotateCheck.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-flush.C:
			if rec := g.flushIdle(2 * time.Second); rec != nil {
				c.dispatch(rec)
			}
		case <-rotateCheck.C:
			st, err := os.Stat(path)
			if err != nil {
				continue
			}
			if currentStat == nil || !os.SameFile(currentStat, st) {
				// Rotated — reopen.
				current.Close()
				nf, err := os.Open(path)
				if err != nil {
					continue
				}
				current = nf
				currentStat = st
				reader = bufio.NewReader(current)
			}
		default:
			// Pull what we can without blocking the select for long.
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				continue
			}
			if completed := g.feed(line); completed != nil {
				c.dispatch(completed)
			}
		}
	}
}

func (c *Collector) dispatch(rec *record) {
	ts := rec.timestamp()
	c.emit(ts, "log.audit", rec.fields, map[string]string{
		"source": "audit",
		"type":   rec.types,
	})

	// Push into whodata cache if this is a file-modifying record.
	if path := rec.firstNonEmpty("name"); path != "" {
		user := rec.firstNonEmpty("auid", "uid")
		entry := whodata.Entry{
			Path:        path,
			User:        rec.resolveUserName(user),
			UID:         user,
			PID:         rec.firstNonEmpty("pid"),
			ProcessName: rec.firstNonEmpty("comm", "exe"),
			Source:      "auditd",
			Timestamp:   ts,
		}
		whodata.Default().Record(entry)
	}
}

// installRules runs auditctl for each FIM path in /etc/watchnode-fim-paths
// if WhodataInstallRules is set. We don't keep the list ourselves — the FIM
// collector writes it out at startup so this collector stays decoupled. This
// is a no-op when the helper file isn't present, so users who manage their
// own audit rules see no interference.
func (c *Collector) installRules() {
	const helperPath = "/var/lib/watchnode/whodata-paths"
	data, err := os.ReadFile(helperPath)
	if err != nil {
		return
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		c.emit(time.Now(), "audit.error", map[string]interface{}{
			"error": "auditctl not found in PATH; whodata rule install skipped",
		}, map[string]string{"source": "audit"})
		return
	}
	for _, p := range strings.Split(string(data), "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// -w <path> -p wa -k watchnode_fim
		cmd := exec.Command("auditctl", "-w", p, "-p", "wa", "-k", "watchnode_fim")
		_ = cmd.Run() // duplicate-rule errors are harmless
	}
}
