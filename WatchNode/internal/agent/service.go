//go:build linux || darwin

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ServiceInstall installs the agent as a system service (systemd on Linux, launchd on macOS).
func ServiceInstall(binaryPath, configPath, logDir string) error {
	if binaryPath == "" {
		var err error
		binaryPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("executable path: %w", err)
		}
	}
	return serviceInstall(binaryPath, configPath, logDir)
}

// ServiceUninstall removes the agent service.
func ServiceUninstall() error {
	return serviceUninstall()
}

// ServiceStart starts the agent service.
func ServiceStart() error {
	return serviceControl("start")
}

// ServiceStop stops the agent service.
func ServiceStop() error {
	return serviceControl("stop")
}

// ServiceStatus returns the service status.
func ServiceStatus() (running bool, err error) {
	return serviceStatus()
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}

func defaultConfigPath() string {
	return filepath.Join("/etc", "watchnode", "agent", "config.yaml")
}
