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
	"time"

	"github.com/watchnode/watchnode/internal/models"
	"go.uber.org/zap"
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
	"kill-process":    true,
	"restart-service": true,
	"disable-account": true,
	"firewall-drop":   true,
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
		return runDisableAccount(arg, a.commandTimeout())
	case "firewall-drop":
		if err := validateFirewallTarget(arg); err != nil {
			return err
		}
		return runFirewallDrop(arg, a.commandTimeout())
	default:
		return fmt.Errorf("unsupported manager command type: %s", commandType)
	}
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

// configUpdatePayload describes the subset of agent config fields that the
// manager is permitted to update at runtime via a config_update command.
// Only included fields are changed; omitted fields remain at their current value.
type configUpdatePayload struct {
	ActiveResponse *struct {
		Enabled            *bool    `json:"enabled"`
		AllowedCommands    []string `json:"allowed_commands"`
		CommandTimeoutSecs *int     `json:"command_timeout_secs"`
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
	}

	return nil
}
