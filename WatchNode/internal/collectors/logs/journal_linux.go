//go:build linux

package logs

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/watchnode/watchnode/internal/models"
)

// runJournal reads from the systemd journal using journalctl.
// It performs an initial backfill of recent entries then tails in real-time.
// Uses journalctl subprocess to avoid a CGO dependency on libsystemd.
func runJournal(ctx context.Context, units []string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	args := []string{
		"--output=json",
		"--follow",
		"--no-pager",
		"-n", "500", // backfill last 500 entries on startup
	}
	for _, u := range units {
		args = append(args, "-u", u)
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		var partial string
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				chunk := partial + string(buf[:n])
				lines := strings.Split(chunk, "\n")
				partial = lines[len(lines)-1]
				for _, line := range lines[:len(lines)-1] {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					dp := parseJournalLine(line)
					select {
					case dataCh <- dp:
					default:
					}
				}
			}
			if readErr != nil {
				break
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-stopCh:
	case <-done:
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	<-done
}

func parseJournalLine(line string) models.DataPoint {
	fields := map[string]interface{}{}
	tags := map[string]string{"source": "journal"}

	if msg := extractJSONField(line, "MESSAGE"); msg != "" {
		fields["message"] = msg
	}
	if priority := extractJSONField(line, "PRIORITY"); priority != "" {
		fields["priority"] = priority
		fields["level"] = journalPriorityName(priority)
	}

	unit := extractJSONField(line, "_SYSTEMD_UNIT")
	if unit == "" {
		unit = extractJSONField(line, "SYSLOG_IDENTIFIER")
	}
	if unit != "" {
		fields["unit"] = unit
		tags["unit"] = unit
	}

	if hostname := extractJSONField(line, "_HOSTNAME"); hostname != "" {
		fields["hostname"] = hostname
	}
	if pid := extractJSONField(line, "_PID"); pid != "" {
		fields["pid"] = pid
	}
	if comm := extractJSONField(line, "_COMM"); comm != "" {
		fields["process"] = comm
	}

	ts := time.Now()
	if usec := extractJSONField(line, "__REALTIME_TIMESTAMP"); usec != "" {
		if t := parseJournalUsec(usec); !t.IsZero() {
			ts = t
		}
	}

	return models.DataPoint{
		Timestamp: ts,
		Type:      "log.journal",
		Fields:    fields,
		Tags:      tags,
	}
}

func extractJSONField(json, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(json, needle)
	if idx == -1 {
		return ""
	}
	rest := json[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end == -1 {
		return ""
	}
	return rest[:end]
}

func journalPriorityName(p string) string {
	switch p {
	case "0":
		return "emergency"
	case "1":
		return "alert"
	case "2":
		return "critical"
	case "3":
		return "error"
	case "4":
		return "warning"
	case "5":
		return "notice"
	case "6":
		return "info"
	case "7":
		return "debug"
	default:
		return p
	}
}

func parseJournalUsec(s string) time.Time {
	var usec int64
	if _, err := fmt.Sscanf(s, "%d", &usec); err != nil {
		return time.Time{}
	}
	return time.Unix(usec/1_000_000, (usec%1_000_000)*1000)
}
