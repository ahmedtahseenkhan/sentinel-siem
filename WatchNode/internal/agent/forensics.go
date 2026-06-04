package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// runCollectArtifact gathers a forensic snapshot, zips it, and uploads it to the
// manager's ingest endpoint (authenticated with the enroll token the agent
// already holds).
func (a *Agent) runCollectArtifact(arg string) error {
	bundle, err := a.gatherArtifacts()
	if err != nil {
		return fmt.Errorf("collect-artifact: %w", err)
	}
	return a.uploadArtifact(bundle)
}

func (a *Agent) gatherArtifacts() (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	add := func(name, content string) {
		if f, err := zw.Create(name); err == nil {
			_, _ = f.Write([]byte(content))
		}
	}

	add("manifest.txt", fmt.Sprintf("agent_id: %s\nhostname: %s\ncollected_at: %s\nos: %s/%s\n",
		a.Info.ID, a.Info.Hostname, time.Now().UTC().Format(time.RFC3339), runtime.GOOS, runtime.GOARCH))
	add("processes.txt", collectProcesses())
	add("network.txt", collectNetwork())
	for name, args := range osArtifactCommands() {
		add(name, runCmdCapture(args))
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

func collectProcesses() string {
	procs, err := process.Processes()
	if err != nil {
		return "error: " + err.Error()
	}
	var b strings.Builder
	b.WriteString("PID\tPPID\tUSER\tNAME\tCMDLINE\n")
	for _, p := range procs {
		ppid, _ := p.Ppid()
		name, _ := p.Name()
		user, _ := p.Username()
		cmd, _ := p.Cmdline()
		fmt.Fprintf(&b, "%d\t%d\t%s\t%s\t%s\n", p.Pid, ppid, user, name, cmd)
	}
	return b.String()
}

func collectNetwork() string {
	conns, err := psnet.Connections("all")
	if err != nil {
		return "error: " + err.Error()
	}
	var b strings.Builder
	b.WriteString("PROTO\tLADDR\tRADDR\tSTATUS\tPID\n")
	for _, c := range conns {
		laddr := fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
		raddr := fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\n", c.Type, laddr, raddr, c.Status, c.Pid)
	}
	return b.String()
}

// osArtifactCommands returns filename -> command (argv) for OS-specific captures.
func osArtifactCommands() map[string][]string {
	if runtime.GOOS == "windows" {
		return map[string][]string{
			"autoruns_hklm_run.txt": {"reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
			"autoruns_hkcu_run.txt": {"reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
			"scheduled_tasks.csv":   {"schtasks", "/query", "/fo", "CSV", "/v"},
			"tasklist.txt":          {"tasklist", "/v"},
			"netstat.txt":           {"netstat", "-ano"},
			"prefetch_listing.txt":  {"cmd", "/c", `dir C:\Windows\Prefetch`},
		}
	}
	return map[string][]string{
		"ps.txt":            {"ps", "aux"},
		"ss.txt":            {"ss", "-tunap"},
		"crontab.txt":       {"crontab", "-l"},
		"tmp_listing.txt":   {"ls", "-la", "/tmp"},
		"auth_log_tail.txt": {"sh", "-c", "tail -n 500 /var/log/auth.log 2>/dev/null || tail -n 500 /var/log/secure 2>/dev/null"},
	}
}

func runCmdCapture(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return string(out) + "\n[command error: " + err.Error() + "]"
	}
	return string(out)
}

func (a *Agent) uploadArtifact(buf *bytes.Buffer) error {
	host := a.Config.Manager.URL
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// The manager's REST API listens on 9400 in this stack.
	url := fmt.Sprintf("http://%s:9400/ingest/artifact/%s", host, a.Info.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		return err
	}
	req.Header.Set("X-Enroll-Token", a.Config.Manager.EnrollToken)
	req.Header.Set("Content-Type", "application/zip")

	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("upload: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
