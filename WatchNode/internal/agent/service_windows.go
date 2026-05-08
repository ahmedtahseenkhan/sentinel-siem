//go:build windows

package agent

import (
	"fmt"
)

// ServiceInstall installs the agent as a Windows Service (stub; use NSSM or sc.exe in scripts).
func ServiceInstall(binaryPath, configPath, logDir string) error {
	return fmt.Errorf("Windows service install: use scripts/install-windows.ps1 or NSSM")
}

// ServiceUninstall removes the agent service.
func ServiceUninstall() error {
	return fmt.Errorf("Windows service uninstall: use scripts or sc delete")
}

// ServiceStart starts the agent service.
func ServiceStart() error {
	return fmt.Errorf("Windows: use net start WatchNodeAgent")
}

// ServiceStop stops the agent service.
func ServiceStop() error {
	return fmt.Errorf("Windows: use net stop WatchNodeAgent")
}

// ServiceStatus returns the service status.
func ServiceStatus() (running bool, err error) {
	return false, fmt.Errorf("Windows: use sc query WatchNodeAgent")
}
