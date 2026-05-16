//go:build windows

package syscollector

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

func (c *Collector) collectServices(ts time.Time) {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return
	}

	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		status, err := s.Query()
		if err != nil {
			s.Close()
			continue
		}

		conf, err := s.Config()
		if err != nil {
			s.Close()
			continue
		}

		fields := map[string]interface{}{
			"name":         name,
			"display_name": conf.DisplayName,
			"state":        serviceState(uint32(status.State)),
			"start_type":   serviceStartType(uint32(conf.StartType)),
			"binary_path":  conf.BinaryPathName,
			"description":  conf.Description,
		}
		if status.ProcessId != 0 {
			fields["pid"] = status.ProcessId
		}

		s.Close()

		c.emit(ts, "syscollector.services", fields, map[string]string{
			"service_name": name,
		})
	}
}

func serviceState(s uint32) string {
	switch s {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

func serviceStartType(t uint32) string {
	switch t {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "auto"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
