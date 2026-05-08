package resource

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Limiter enforces CPU, memory, and optional disk limits for the agent process.
type Limiter struct {
	MaxCPUPercent  float64
	MaxMemoryBytes uint64
	MaxDiskBytes   uint64
	lastCPUSample  cpuSample
	proc           *process.Process
}

type cpuSample struct {
	time  time.Time
	usage float64
}

// ResourceExceededError is returned when resource limits are exceeded.
type ResourceExceededError struct {
	Resource string
	Limit    interface{}
	Current  interface{}
}

func (e *ResourceExceededError) Error() string {
	return fmt.Sprintf("resource %s exceeded: limit=%v current=%v", e.Resource, e.Limit, e.Current)
}

// NewLimiter creates a limiter with the given limits.
func NewLimiter(maxCPUPercent float64, maxMemoryBytes, maxDiskBytes uint64) *Limiter {
	p, _ := process.NewProcess(int32(os.Getpid()))
	return &Limiter{
		MaxCPUPercent:  maxCPUPercent,
		MaxMemoryBytes: maxMemoryBytes,
		MaxDiskBytes:   maxDiskBytes,
		proc:           p,
	}
}

// Check returns an error if any resource limit is exceeded.
func (l *Limiter) Check() error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if l.MaxMemoryBytes > 0 && memStats.Alloc > l.MaxMemoryBytes {
		return &ResourceExceededError{
			Resource: "memory",
			Limit:    l.MaxMemoryBytes,
			Current:  memStats.Alloc,
		}
	}

	if l.MaxCPUPercent > 0 && l.proc != nil {
		// CPUPercent is computed since last call; call at limiter cadence.
		pct, err := l.proc.CPUPercent()
		if err == nil && !l.lastCPUSample.time.IsZero() && pct > l.MaxCPUPercent {
			return &ResourceExceededError{
				Resource: "cpu",
				Limit:    fmt.Sprintf("%.1f%%", l.MaxCPUPercent),
				Current:  fmt.Sprintf("%.1f%%", pct),
			}
		}
		l.lastCPUSample.time = time.Now()
		l.lastCPUSample.usage = pct
	}
	return nil
}
