//go:build darwin

package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.watchnode.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>--config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`
	plistName = "com.watchnode.agent.plist"
)

func serviceInstall(binaryPath, configPath, logDir string) error {
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	plistContent := fmt.Sprintf(launchdPlist, binaryPath, configPath)
	destDir := filepath.Join("/Library", "LaunchDaemons")
	plistPath := filepath.Join(destDir, plistName)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	return runCommand("launchctl", "load", plistPath)
}

func serviceUninstall() error {
	plistPath := filepath.Join("/Library", "LaunchDaemons", plistName)
	_ = runCommand("launchctl", "unload", plistPath)
	return os.Remove(plistPath)
}

func serviceControl(action string) error {
	plistPath := filepath.Join("/Library", "LaunchDaemons", plistName)
	switch action {
	case "start":
		return runCommand("launchctl", "load", plistPath)
	case "stop":
		return runCommand("launchctl", "unload", plistPath)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func serviceStatus() (running bool, err error) {
	// launchctl list returns 0; check for com.watchnode.agent
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return false, err
	}
	running = bytes.Contains(out, []byte("com.watchnode.agent"))
	return running, nil
}
