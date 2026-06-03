package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Application control (pre-execution prevention) via Windows AppLocker.
//
// The manager sends an "app-control" command with a mode (audit | enforce |
// clear). The agent applies Microsoft's "default rules" AppLocker policy at the
// requested enforcement level. Those defaults allow Everyone to run from
// %PROGRAMFILES% and %WINDIR% and Administrators to run anything — so non-admin
// execution from user-writable locations (Downloads, %TEMP%, %APPDATA%) is
// blocked. That single baseline stops most commodity malware and ransomware,
// which run from exactly those folders, and it's kernel-enforced by Windows —
// real pre-execution prevention without a custom driver.
//
// NOTE: AppLocker *enforcement* requires Windows Enterprise/Education or Server
// (Pro can audit). Start in audit mode, review the AppLocker event channels the
// agent already collects, then enforce.

// %[1]s is the EnforcementMode; literal percent signs are doubled for Sprintf.
const appLockerPolicyTemplate = `<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="%[1]s">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default) All files in Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%%PROGRAMFILES%%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default) All files in Windows folder" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%%WINDIR%%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default) All files for Administrators" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="%[1]s">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default) All scripts in Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%%PROGRAMFILES%%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default) All scripts in Windows folder" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%%WINDIR%%\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default) All scripts for Administrators" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="%[1]s">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default) All Windows Installer files in Windows\Installer" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%%WINDIR%%\Installer\*"/></Conditions>
    </FilePathRule>
    <FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="(Default) All Windows Installer files for Administrators" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>`

var appControlModes = map[string]string{
	"audit":   "AuditOnly",
	"enforce": "Enabled",
	"clear":   "NotConfigured",
	"off":     "NotConfigured",
}

// runAppControl applies the AppLocker baseline at the requested mode.
func (a *Agent) runAppControl(arg string) error {
	mode := parseAppControlMode(arg)
	enforcement, ok := appControlModes[mode]
	if !ok {
		return fmt.Errorf("app-control: mode must be audit|enforce|clear (got %q)", mode)
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("app-control: only supported on Windows (AppLocker)")
	}
	return applyAppLocker(enforcement, a.commandTimeout())
}

// parseAppControlMode accepts {"mode":"audit"}, "audit", or audit.
func parseAppControlMode(arg string) string {
	arg = strings.TrimSpace(arg)
	var obj struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(arg), &obj) == nil && obj.Mode != "" {
		return strings.ToLower(strings.TrimSpace(obj.Mode))
	}
	return strings.ToLower(strings.Trim(arg, `"`))
}

func applyAppLocker(enforcement string, timeout time.Duration) error {
	policy := fmt.Sprintf(appLockerPolicyTemplate, enforcement)
	tmp := filepath.Join(os.TempDir(), "sentinel_applocker.xml")
	if err := os.WriteFile(tmp, []byte(policy), 0o600); err != nil {
		return fmt.Errorf("app-control: write policy: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// AppLocker enforcement requires the Application Identity service running.
	ps := fmt.Sprintf(
		`Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue; `+
			`Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue; `+
			`Set-AppLockerPolicy -XmlPolicy '%s'`, tmp)
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("app-control: Set-AppLockerPolicy failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
