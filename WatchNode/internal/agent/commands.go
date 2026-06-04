package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/models"
	"go.uber.org/zap"
)

// activeBlocks tracks IPs currently blocked by this agent so duplicate
// firewall-drop commands are idempotent. Keyed by IP string.
var (
	activeBlocksMu sync.Mutex
	activeBlocks   = map[string]time.Time{}
)

// Argument validators — strict allowlists per command type.
// These prevent command injection by ensuring the manager-supplied argument
// cannot contain shell metacharacters or escape the intended operation.
var (
	// reValidPID matches a plain integer process ID (no leading zeros beyond "0").
	reValidPID = regexp.MustCompile(`^\d+$`)

	// reValidProcessName allows safe process names: alphanumeric, dots, hyphens,
	// underscores. No spaces, slashes, quotes, or shell metacharacters.
	reValidProcessName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

	// reValidServiceName matches systemd / Windows service names.
	reValidServiceName = regexp.MustCompile(`^[a-zA-Z0-9._@-]{1,128}$`)

	// reValidUsername matches POSIX-safe usernames.
	reValidUsername = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

// validateFirewallTarget returns an error if target is not a valid IP address
// (IPv4 or IPv6). This prevents injecting extra tokens into netsh / iptables.
func validateFirewallTarget(target string) error {
	if net.ParseIP(target) == nil {
		return fmt.Errorf("firewall-drop: argument %q is not a valid IP address", target)
	}
	return nil
}

// validateProcessTarget returns an error if target is not a safe PID or
// process-name string.
func validateProcessTarget(target string) error {
	if reValidPID.MatchString(target) {
		return nil
	}
	if reValidProcessName.MatchString(target) {
		return nil
	}
	return fmt.Errorf("kill-process: argument %q is not a valid PID or process name", target)
}

// validateServiceName returns an error if serviceName contains unsafe characters.
func validateServiceName(serviceName string) error {
	if !reValidServiceName.MatchString(serviceName) {
		return fmt.Errorf("restart-service: argument %q is not a valid service name", serviceName)
	}
	return nil
}

// validateUsername returns an error if username contains unsafe characters.
func validateUsername(username string) error {
	if !reValidUsername.MatchString(username) {
		return fmt.Errorf("disable-account: argument %q is not a valid username", username)
	}
	return nil
}

// defaultBuiltinCommands is the set of commands available when AllowedCommands
// is empty but ActiveResponse.Enabled is true.
var defaultBuiltinCommands = map[string]bool{
	"kill-process":     true,
	"restart-service":  true,
	"disable-account":  true,
	"firewall-drop":    true,
	"firewall-unblock": true,
	"isolate-host":     true,
	"unisolate-host":   true,
	"app-control":      true,
	"quarantine-file":  true,
	"force-logoff":     true,
	"collect-artifact": true,
}

func (a *Agent) commandTimeout() time.Duration {
	a.configMu.RLock()
	s := a.Config.ActiveResponse.CommandTimeoutSecs
	a.configMu.RUnlock()
	if s <= 0 {
		return 15 * time.Second
	}
	return time.Duration(s) * time.Second
}

func (a *Agent) commandAllowed(commandType string) bool {
	a.configMu.RLock()
	enabled := a.Config.ActiveResponse.Enabled
	allowed := a.Config.ActiveResponse.AllowedCommands
	a.configMu.RUnlock()

	if !enabled {
		return false
	}
	if len(allowed) == 0 {
		return defaultBuiltinCommands[commandType]
	}
	for _, c := range allowed {
		if c == commandType {
			return true
		}
	}
	return false
}

func (a *Agent) handleManagerCommand(commandType string, payload []byte) {
	commandType = strings.TrimSpace(commandType)
	arg := strings.TrimSpace(string(payload))

	if commandType == "" {
		a.Logger.Warn("received manager command with empty type")
		return
	}

	// config_update bypasses the active-response allowlist — it is a privileged
	// system command sent by the manager to update the agent configuration.
	if commandType == "config_update" {
		if err := a.handleConfigUpdate(payload); err != nil {
			a.Logger.Error("config update failed", zap.Error(err))
			a.reportCommandResult(commandType, "", "failed", err.Error())
		} else {
			a.Logger.Info("agent config updated by manager")
			a.reportCommandResult(commandType, "", "executed", "")
		}
		return
	}

	if !a.commandAllowed(commandType) {
		a.Logger.Warn("manager command not in allowlist — ignored",
			zap.String("command_type", commandType),
		)
		a.reportCommandResult(commandType, arg, "denied", "command not in allowlist")
		return
	}

	a.Logger.Info("executing manager command",
		zap.String("command_type", commandType),
		zap.String("argument", arg),
	)

	err := a.executeCommand(commandType, arg)
	if err != nil {
		a.Logger.Error("manager command execution failed",
			zap.String("command_type", commandType),
			zap.String("argument", arg),
			zap.Error(err),
		)
		a.reportCommandResult(commandType, arg, "failed", err.Error())
		return
	}

	a.Logger.Info("manager command executed successfully",
		zap.String("command_type", commandType),
		zap.String("argument", arg),
	)
	a.reportCommandResult(commandType, arg, "executed", "")
}

// reportCommandResult emits a telemetry data point so WatchTower can track
// command execution status per agent.
func (a *Agent) reportCommandResult(commandType, argument, status, errMsg string) {
	fields := map[string]interface{}{
		"command_type": commandType,
		"argument":     argument,
		"status":       status,
	}
	if errMsg != "" {
		fields["error"] = errMsg
	}
	dp := models.DataPoint{
		Timestamp: time.Now(),
		Type:      "active_response.result",
		Fields:    fields,
		Tags: map[string]string{
			"agent_id": a.Info.ID,
		},
	}
	select {
	case a.dataCh <- dp:
	default:
		a.Logger.Warn("data channel full, dropping command result event")
	}
}

func (a *Agent) executeCommand(commandType, arg string) error {
	switch commandType {
	case "kill-process":
		if err := validateProcessTarget(arg); err != nil {
			return err
		}
		return runKillProcess(arg, a.commandTimeout())
	case "restart-service":
		if err := validateServiceName(arg); err != nil {
			return err
		}
		return runRestartService(arg, a.commandTimeout())
	case "disable-account":
		if err := validateUsername(arg); err != nil {
			return err
		}
		if a.userSafelisted(arg) {
			return fmt.Errorf("disable-account: user %q is in safelist", arg)
		}
		return runDisableAccount(arg, a.commandTimeout())
	case "firewall-drop":
		if err := validateFirewallTarget(arg); err != nil {
			return err
		}
		if a.ipSafelisted(arg) {
			return fmt.Errorf("firewall-drop: ip %q is in safelist", arg)
		}
		if alreadyBlocked(arg) {
			// Idempotent: skip the netsh/iptables call entirely, but still
			// report executed so the manager sees the policy was satisfied.
			return nil
		}
		if err := runFirewallDrop(arg, a.commandTimeout()); err != nil {
			return err
		}
		recordBlock(arg)
		// Schedule auto-unblock if a TTL is configured.
		a.configMu.RLock()
		ttl := a.Config.ActiveResponse.BlockTTLSecs
		a.configMu.RUnlock()
		if ttl > 0 {
			go a.scheduleUnblock(arg, time.Duration(ttl)*time.Second)
		}
		return nil
	case "firewall-unblock":
		if err := validateFirewallTarget(arg); err != nil {
			return err
		}
		err := runFirewallUnblock(arg, a.commandTimeout())
		forgetBlock(arg)
		return err
	case "isolate-host":
		return a.runIsolateHost()
	case "unisolate-host":
		return a.runUnisolateHost()
	case "app-control":
		return a.runAppControl(arg)
	case "quarantine-file":
		return a.runQuarantineFile(arg)
	case "force-logoff":
		return a.runForceLogoff(arg)
	case "collect-artifact":
		return a.runCollectArtifact(arg)
	default:
		return fmt.Errorf("unsupported manager command type: %s", commandType)
	}
}

// ipSafelisted returns true if target matches any safelist entry. Entries may
// be a bare IP or a CIDR.
func (a *Agent) ipSafelisted(target string) bool {
	ip := net.ParseIP(target)
	if ip == nil {
		return false
	}
	a.configMu.RLock()
	safelist := a.Config.ActiveResponse.SafelistIPs
	a.configMu.RUnlock()
	for _, entry := range safelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil && ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if net.ParseIP(entry) != nil && entry == target {
			return true
		}
	}
	return false
}

// userSafelisted returns true if username is in the safelist (case-insensitive).
func (a *Agent) userSafelisted(username string) bool {
	a.configMu.RLock()
	safelist := a.Config.ActiveResponse.SafelistUsers
	a.configMu.RUnlock()
	low := strings.ToLower(username)
	for _, entry := range safelist {
		if strings.ToLower(strings.TrimSpace(entry)) == low {
			return true
		}
	}
	return false
}

// alreadyBlocked reports whether target was blocked by this agent and the
// block has not yet expired according to bookkeeping.
func alreadyBlocked(target string) bool {
	activeBlocksMu.Lock()
	defer activeBlocksMu.Unlock()
	_, ok := activeBlocks[target]
	return ok
}

func recordBlock(target string) {
	activeBlocksMu.Lock()
	activeBlocks[target] = time.Now()
	activeBlocksMu.Unlock()
}

func forgetBlock(target string) {
	activeBlocksMu.Lock()
	delete(activeBlocks, target)
	activeBlocksMu.Unlock()
}

// scheduleUnblock runs runFirewallUnblock after ttl has elapsed, regardless of
// whether the manager sends an explicit firewall-unblock command. Survives
// across rule re-fires because recordBlock keeps the entry until TTL.
func (a *Agent) scheduleUnblock(target string, ttl time.Duration) {
	time.Sleep(ttl)
	if err := runFirewallUnblock(target, a.commandTimeout()); err != nil {
		a.Logger.Warn("auto-unblock failed",
			zap.String("target", target),
			zap.Error(err),
		)
	} else {
		a.Logger.Info("auto-unblock executed",
			zap.String("target", target),
			zap.Duration("ttl", ttl),
		)
	}
	forgetBlock(target)
	a.reportCommandResult("firewall-unblock", target, "executed", "auto-ttl")
}

func runKillProcess(target string, timeout time.Duration) error {
	if target == "" {
		return fmt.Errorf("missing process target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if runtime.GOOS == "windows" {
		if _, err := strconv.Atoi(target); err == nil {
			return exec.CommandContext(ctx, "taskkill", "/PID", target, "/F").Run()
		}
		return exec.CommandContext(ctx, "taskkill", "/IM", target, "/F").Run()
	}
	if _, err := strconv.Atoi(target); err == nil {
		return exec.CommandContext(ctx, "kill", "-9", target).Run()
	}
	return exec.CommandContext(ctx, "pkill", "-f", target).Run()
}

func runRestartService(serviceName string, timeout time.Duration) error {
	if serviceName == "" {
		return fmt.Errorf("missing service name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if runtime.GOOS == "windows" {
		if err := exec.CommandContext(ctx, "sc", "stop", serviceName).Run(); err != nil {
			return err
		}
		return exec.CommandContext(ctx, "sc", "start", serviceName).Run()
	}
	return exec.CommandContext(ctx, "systemctl", "restart", serviceName).Run()
}

func runDisableAccount(username string, timeout time.Duration) error {
	if username == "" {
		return fmt.Errorf("missing username")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "net", "user", username, "/active:no").Run()
	}
	return exec.CommandContext(ctx, "usermod", "-L", username).Run()
}

func runFirewallDrop(target string, timeout time.Duration) error {
	if target == "" {
		return fmt.Errorf("missing target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if runtime.GOOS == "windows" {
		ruleName := "WatchNode_Block_" + target
		return exec.CommandContext(ctx,
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=block",
			"remoteip="+target,
		).Run()
	}

	return exec.CommandContext(ctx, "iptables", "-A", "INPUT", "-s", target, "-j", "DROP").Run()
}

// runFirewallUnblock reverses runFirewallDrop. On Windows we delete by the
// deterministic rule name; on Linux we issue iptables -D with the same
// arguments. Both are tolerant of "not found" (returns nil) since the rule
// may have been removed manually or by a TTL race.
func runFirewallUnblock(target string, timeout time.Duration) error {
	if target == "" {
		return fmt.Errorf("missing target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if runtime.GOOS == "windows" {
		ruleName := "WatchNode_Block_" + target
		// netsh exits 1 if rule not found; treat as success for idempotency.
		_ = exec.CommandContext(ctx,
			"netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+ruleName,
		).Run()
		return nil
	}
	_ = exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-s", target, "-j", "DROP").Run()
	return nil
}

// ── Host isolation ──────────────────────────────────────────────────────────────
// isolate-host quarantines the endpoint: it blocks all network traffic EXCEPT the
// channel back to WatchTower, so a compromised box is contained but the manager can
// still send the un-isolate command. Two hard safety rules:
//   1. We resolve the manager's IP(s) BEFORE blocking and refuse to isolate if we
//      can't — otherwise we'd cut our own lifeline and the host could never be
//      released remotely.
//   2. If a block TTL is configured, we schedule an auto-unisolate so a mistaken or
//      stranded isolation self-heals.
var (
	isolationMu     sync.Mutex
	isolationActive bool
	isolationIPs    []string // manager IPs allow-listed during the current isolation
)

// managerAllowIPs resolves the manager host (from manager.url) to one or more IPs
// while the network is still up. Returns nil if it can't be resolved.
func (a *Agent) managerAllowIPs() []string {
	a.configMu.RLock()
	url := a.Config.Manager.URL
	a.configMu.RUnlock()
	host := url
	if h, _, err := net.SplitHostPort(url); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	return ips
}

func isolateRuleName(ip, dir string) string {
	return "WatchNode_Isolate_" + strings.ReplaceAll(ip, ":", "_") + "_" + dir
}

func (a *Agent) runIsolateHost() error {
	isolationMu.Lock()
	defer isolationMu.Unlock()
	if isolationActive {
		return nil // idempotent
	}
	ips := a.managerAllowIPs()
	if len(ips) == 0 {
		return fmt.Errorf("isolate-host: cannot resolve manager address — refusing to isolate (would lose remote control)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.commandTimeout())
	defer cancel()
	if err := isolateNetwork(ctx, ips); err != nil {
		return err
	}
	isolationActive = true
	isolationIPs = ips

	// Safety net: auto-release after the configured TTL so a stranded isolation
	// can't brick the host permanently.
	a.configMu.RLock()
	ttl := a.Config.ActiveResponse.BlockTTLSecs
	a.configMu.RUnlock()
	if ttl > 0 {
		go a.scheduleUnisolate(time.Duration(ttl) * time.Second)
	}
	return nil
}

func (a *Agent) runUnisolateHost() error {
	isolationMu.Lock()
	defer isolationMu.Unlock()
	ips := isolationIPs
	if len(ips) == 0 {
		// State lost (e.g. agent restarted while isolated) — re-resolve so we can
		// still tear down the per-IP allow rules by their deterministic names.
		ips = a.managerAllowIPs()
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.commandTimeout())
	defer cancel()
	err := unisolateNetwork(ctx, ips)
	isolationActive = false
	isolationIPs = nil
	return err
}

// scheduleUnisolate releases isolation after ttl, unless it was already lifted.
func (a *Agent) scheduleUnisolate(ttl time.Duration) {
	time.Sleep(ttl)
	isolationMu.Lock()
	active := isolationActive
	isolationMu.Unlock()
	if !active {
		return
	}
	if err := a.runUnisolateHost(); err != nil {
		a.Logger.Warn("auto-unisolate failed", zap.Error(err))
		return
	}
	a.Logger.Info("auto-unisolate executed (TTL safety net)", zap.Duration("ttl", ttl))
	a.reportCommandResult("unisolate-host", "", "executed", "auto-ttl")
}

// isolateNetwork blocks all traffic except loopback, established flows, and the
// manager IPs. Windows uses the default firewall policy + allow rules; Linux uses
// iptables. managerIPs is guaranteed non-empty by the caller.
func isolateNetwork(ctx context.Context, managerIPs []string) error {
	if runtime.GOOS == "windows" {
		// Allow the manager channel first, THEN flip the default to block.
		for _, ip := range managerIPs {
			_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				"name="+isolateRuleName(ip, "out"), "dir=out", "action=allow", "remoteip="+ip).Run()
			_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				"name="+isolateRuleName(ip, "in"), "dir=in", "action=allow", "remoteip="+ip).Run()
		}
		// The Windows firewall is stateful, so replies to the (allowed) outbound
		// manager connection are permitted even with inbound blocked.
		return exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,blockoutbound").Run()
	}

	// Linux: insert allow rules at the top, then default-drop the chains.
	run := func(args ...string) { _ = exec.CommandContext(ctx, "iptables", args...).Run() }
	run("-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT")
	run("-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT")
	run("-I", "INPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	run("-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	for _, ip := range managerIPs {
		run("-I", "OUTPUT", "1", "-d", ip, "-j", "ACCEPT")
		run("-I", "INPUT", "1", "-s", ip, "-j", "ACCEPT")
	}
	if err := exec.CommandContext(ctx, "iptables", "-P", "INPUT", "DROP").Run(); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "iptables", "-P", "OUTPUT", "DROP").Run()
}

// unisolateNetwork reverses isolateNetwork. Tolerant of "not found" since rules
// may have been removed manually or the policy already restored.
func unisolateNetwork(ctx context.Context, managerIPs []string) error {
	if runtime.GOOS == "windows" {
		// Restore the normal default (inbound blocked, outbound allowed) first so
		// connectivity returns even if rule deletion below partially fails.
		err := exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,allowoutbound").Run()
		for _, ip := range managerIPs {
			_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+isolateRuleName(ip, "out")).Run()
			_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+isolateRuleName(ip, "in")).Run()
		}
		return err
	}

	// Linux: restore accept policy, then remove the allow rules we inserted.
	_ = exec.CommandContext(ctx, "iptables", "-P", "INPUT", "ACCEPT").Run()
	_ = exec.CommandContext(ctx, "iptables", "-P", "OUTPUT", "ACCEPT").Run()
	run := func(args ...string) { _ = exec.CommandContext(ctx, "iptables", args...).Run() }
	for _, ip := range managerIPs {
		run("-D", "OUTPUT", "-d", ip, "-j", "ACCEPT")
		run("-D", "INPUT", "-s", ip, "-j", "ACCEPT")
	}
	run("-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	run("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	run("-D", "INPUT", "-i", "lo", "-j", "ACCEPT")
	run("-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	return nil
}

// configUpdatePayload describes the subset of agent config fields that the
// manager is permitted to update at runtime via a config_update command.
// Only included fields are changed; omitted fields remain at their current value.
type configUpdatePayload struct {
	ActiveResponse *struct {
		Enabled            *bool    `json:"enabled"`
		AllowedCommands    []string `json:"allowed_commands"`
		CommandTimeoutSecs *int     `json:"command_timeout_secs"`
		BlockTTLSecs       *int     `json:"block_ttl_secs"`
		SafelistIPs        []string `json:"safelist_ips"`
		SafelistUsers      []string `json:"safelist_users"`
	} `json:"active_response,omitempty"`
}

// handleConfigUpdate applies a partial config update received from the manager.
func (a *Agent) handleConfigUpdate(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty config_update payload")
	}

	var patch configUpdatePayload
	if err := json.Unmarshal(payload, &patch); err != nil {
		return fmt.Errorf("parse config_update payload: %w", err)
	}

	a.configMu.Lock()
	defer a.configMu.Unlock()

	if patch.ActiveResponse != nil {
		ar := patch.ActiveResponse
		if ar.Enabled != nil {
			a.Config.ActiveResponse.Enabled = *ar.Enabled
		}
		if ar.AllowedCommands != nil {
			// Defensive copy to avoid external mutation of the slice.
			cmds := make([]string, len(ar.AllowedCommands))
			copy(cmds, ar.AllowedCommands)
			a.Config.ActiveResponse.AllowedCommands = cmds
		}
		if ar.CommandTimeoutSecs != nil && *ar.CommandTimeoutSecs > 0 {
			a.Config.ActiveResponse.CommandTimeoutSecs = *ar.CommandTimeoutSecs
		}
		if ar.BlockTTLSecs != nil {
			a.Config.ActiveResponse.BlockTTLSecs = *ar.BlockTTLSecs
		}
		if ar.SafelistIPs != nil {
			cp := make([]string, len(ar.SafelistIPs))
			copy(cp, ar.SafelistIPs)
			a.Config.ActiveResponse.SafelistIPs = cp
		}
		if ar.SafelistUsers != nil {
			cp := make([]string, len(ar.SafelistUsers))
			copy(cp, ar.SafelistUsers)
			a.Config.ActiveResponse.SafelistUsers = cp
		}
	}

	return nil
}
