//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "SentinelWatchNode"
	serviceDisplayName = "Sentinel WatchNode Agent"
	serviceDescription = "Sentinel SIEM endpoint monitoring and telemetry agent"
)

// ServiceInstall registers the agent as a Windows Service using the native SCM
// (no NSSM required). It sets automatic restart-on-failure with 5s/30s/60s
// back-off and marks the service auto-start so it survives reboots.
func ServiceInstall(binaryPath, configPath, _ string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// If service already exists, just update config and failure actions.
	if s, err2 := m.OpenService(serviceName); err2 == nil {
		defer s.Close()
		if err2 = applyFailureActions(s.Handle); err2 != nil {
			return fmt.Errorf("update failure actions: %w", err2)
		}
		fmt.Printf("Service %q already installed — failure actions updated.\n", serviceName)
		return nil
	}

	if configPath == "" {
		// Default config path next to the binary.
		configPath = filepath.Join(filepath.Dir(binaryPath), "agent.yaml")
	}

	s, err := m.CreateService(
		serviceName,
		binaryPath,
		mgr.Config{
			StartType:        mgr.StartAutomatic,
			DisplayName:      serviceDisplayName,
			Description:      serviceDescription,
			ServiceStartName: "LocalSystem",
		},
		// Args passed to the binary when SCM starts it.
		"-config", configPath,
	)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Restart automatically on any failure.
	if err := applyFailureActions(s.Handle); err != nil {
		// Non-fatal — service is installed, recovery just isn't set.
		fmt.Fprintf(os.Stderr, "warning: could not set failure actions: %v\n", err)
	}

	fmt.Printf("Service %q installed. Starting...\n", serviceName)
	return s.Start()
}

// ServiceUninstall stops and removes the Windows service.
func ServiceUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", serviceName, err)
	}
	defer s.Close()

	// Stop first (ignore error — it may already be stopped).
	_, _ = s.Control(svc.Stop)
	time.Sleep(2 * time.Second)

	return s.Delete()
}

// ServiceStart starts an already-installed service.
func ServiceStart() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service not found: %w", err)
	}
	defer s.Close()
	return s.Start()
}

// ServiceStop sends a STOP control to the service.
func ServiceStop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service not found: %w", err)
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}

// ServiceStatus returns whether the service is currently running.
func ServiceStatus() (running bool, err error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false, fmt.Errorf("service not found: %w", err)
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running, nil
}

// IsRunningAsService returns true when the process was started by the SCM.
func IsRunningAsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// ── Windows API types for SERVICE_FAILURE_ACTIONS ────────────────────────────

// scAction mirrors the Win32 SC_ACTION struct.
type scAction struct {
	Type  uint32 // SC_ACTION_TYPE
	Delay uint32 // milliseconds
}

// serviceFailureActions mirrors the Win32 SERVICE_FAILURE_ACTIONS struct.
type serviceFailureActions struct {
	ResetPeriod  uint32         // seconds; 0 = never reset
	RebootMsg    *uint16        // nil
	Command      *uint16        // nil
	ActionsCount uint32
	Actions      *scAction
}

const (
	scActionRestart  = 1 // SC_ACTION_RESTART
	serviceConfigFailureActions = 2 // SERVICE_CONFIG_FAILURE_ACTIONS
)

// applyFailureActions sets the SCM recovery policy on an open service handle:
// restart after 5 s, 30 s, then 60 s on every subsequent crash.
// Counters reset after 24 hours of clean uptime.
func applyFailureActions(handle windows.Handle) error {
	actions := []scAction{
		{Type: scActionRestart, Delay: 5_000},  // 1st crash  → wait 5 s
		{Type: scActionRestart, Delay: 30_000}, // 2nd crash  → wait 30 s
		{Type: scActionRestart, Delay: 60_000}, // subsequent → wait 60 s
	}

	sfa := serviceFailureActions{
		ResetPeriod:  86_400, // reset failure counter after 24 h
		ActionsCount: uint32(len(actions)),
		Actions:      &actions[0],
	}

	r1, _, err := procChangeServiceConfig2.Call(
		uintptr(handle),
		serviceConfigFailureActions,
		uintptr(unsafe.Pointer(&sfa)),
	)
	if r1 == 0 {
		return fmt.Errorf("ChangeServiceConfig2: %w", err)
	}
	return nil
}

// Lazy-load advapi32 proc.
var (
	modAdvapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procChangeServiceConfig2 = modAdvapi32.NewProc("ChangeServiceConfig2W")
)
