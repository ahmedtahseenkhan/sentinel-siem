package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Additional active-response actions: quarantine-file and force-logoff.

var reLogoffTarget = regexp.MustCompile(`^[a-zA-Z0-9._\\-]{1,128}$`)

// argField pulls a value from the command payload, accepting either a JSON
// object ({"path":"..."}) or a bare/quoted string.
func argField(arg, field string) string {
	arg = strings.TrimSpace(arg)
	var m map[string]string
	if json.Unmarshal([]byte(arg), &m) == nil {
		if v := strings.TrimSpace(m[field]); v != "" {
			return v
		}
	}
	return strings.Trim(arg, `"`)
}

func quarantineDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "SentinelAgent", "quarantine")
	}
	return "/var/lib/watchnode/quarantine"
}

// isCriticalPath refuses to quarantine OS-critical locations so a response never
// bricks the machine.
func isCriticalPath(p string) bool {
	lp := strings.ToLower(filepath.Clean(p))
	var prefixes []string
	if runtime.GOOS == "windows" {
		prefixes = []string{`c:\windows`, `c:\program files`, `c:\program files (x86)`}
	} else {
		prefixes = []string{"/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot", "/proc", "/sys", "/dev"}
	}
	for _, pre := range prefixes {
		if lp == pre || strings.HasPrefix(lp, pre+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Cross-device (EXDEV): copy then remove.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		in.Close()
		return err
	}
	_, cerr := io.Copy(out, in)
	in.Close()
	out.Close()
	if cerr != nil {
		return cerr
	}
	return os.Remove(src)
}

// runQuarantineFile moves a malicious file into the quarantine dir (preserving
// it for forensics, not deleting) and strips its execute permission.
func (a *Agent) runQuarantineFile(arg string) error {
	path := argField(arg, "path")
	if path == "" {
		return fmt.Errorf("quarantine-file: path required")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("quarantine-file: %v", err)
	}
	if isCriticalPath(path) {
		return fmt.Errorf("quarantine-file: refusing to quarantine system path %q", path)
	}
	qdir := quarantineDir()
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return fmt.Errorf("quarantine-file: %w", err)
	}
	dst := filepath.Join(qdir, fmt.Sprintf("%d_%s.quar", time.Now().Unix(), filepath.Base(path)))
	if err := moveFile(path, dst); err != nil {
		return fmt.Errorf("quarantine-file: move: %w", err)
	}
	_ = os.Chmod(dst, 0o600) // strip execute
	return nil
}

// runForceLogoff forcibly logs off a user session (or a numeric session id).
func (a *Agent) runForceLogoff(arg string) error {
	target := argField(arg, "username")
	if target == "" {
		target = argField(arg, "session")
	}
	if target == "" {
		return fmt.Errorf("force-logoff: username or session id required")
	}
	if !reLogoffTarget.MatchString(target) {
		return fmt.Errorf("force-logoff: invalid target %q", target)
	}
	if a.userSafelisted(target) {
		return fmt.Errorf("force-logoff: %q is in the safelist", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.commandTimeout())
	defer cancel()

	if runtime.GOOS == "windows" {
		if isAllDigits(target) {
			return exec.CommandContext(ctx, "logoff", target).Run()
		}
		// Resolve the user's session id(s) via quser, then log each off.
		ps := fmt.Sprintf(`$u='%s'; (quser) -replace '\s{2,}',',' | ConvertFrom-Csv | `+
			`Where-Object {$_.USERNAME -eq $u} | ForEach-Object { logoff ($_.ID) }`, target)
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
	}

	// Linux: prefer systemd-logind, fall back to killing the user's processes.
	if err := exec.CommandContext(ctx, "loginctl", "terminate-user", target).Run(); err == nil {
		return nil
	}
	return exec.CommandContext(ctx, "pkill", "-KILL", "-u", target).Run()
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
