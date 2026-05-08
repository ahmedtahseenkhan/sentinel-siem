//go:build linux

package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	systemdUnit = `[Unit]
Description=WatchNode Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config %s
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
	unitName = "watchnode.service"
)

func serviceInstall(binaryPath, configPath, logDir string) error {
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	unitContent := fmt.Sprintf(systemdUnit, binaryPath, configPath)
	unitPath := filepath.Join("/etc", "systemd", "system", unitName)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	return runCommand("systemctl", "daemon-reload")
}

func serviceUninstall() error {
	_ = runCommand("systemctl", "stop", unitName)
	unitPath := filepath.Join("/etc", "systemd", "system", unitName)
	_ = os.Remove(unitPath)
	return runCommand("systemctl", "daemon-reload")
}

func serviceControl(action string) error {
	return runCommand("systemctl", action, unitName)
}

func serviceStatus() (running bool, err error) {
	// systemctl is-active returns 0 if active, non-zero otherwise
	err = runCommand("systemctl", "is-active", "--quiet", unitName)
	running = (err == nil)
	if err != nil {
		err = nil
	}
	return running, nil
}
