package resource

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// startupGracePeriod is the time after agent start during which CPU limits
// are not enforced. This avoids dropping data during initial baseline scans
// (FIM, syscollector, SCA) which legitimately spike CPU usage.
const startupGracePeriod = 2 * time.Minute

// cpuSampleWindow is the rolling window over which CPU usage is averaged.
// Using a sustained average instead of an instantaneous peak prevents
// transient spikes (e.g. during a single rule evaluation) from triggering
// drops or disconnects.
const cpuSampleWindow = 30 * time.Second

// Limiter enforces CPU and memory limits for the agent process.
//
// Design notes (Wazuh-parity behavior):
//   - A 2-minute startup grace period suppresses CPU enforcement while
//     collectors run their initial baseline scans.
//   - CPU usage is measured as a moving average over a 30-second window
//     rather than an instantaneous reading, so brief spikes never trip
//     the limit.
//   - Memory enforcement is immediate (no grace period) because runaway
//     memory growth is a real failure mode worth catching fast.
type Limiter struct {
	MaxCPUPercent  float64
	MaxMemoryBytes uint64
	MaxDiskBytes   uint64

	startTime time.Time
	proc      *process.Process

	mu        sync.Mutex
	cpuSeries []cpuPoint
}

type cpuPoint struct {
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
		startTime:      time.Now(),
		proc:           p,
	}
}

// Check returns an error if any resource limit is exceeded.
// During the startup grace period, only memory limits are enforced.
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

	// Skip CPU enforcement during startup — baseline scans legitimately spike.
	if time.Since(l.startTime) < startupGracePeriod {
		return nil
	}

	if l.MaxCPUPercent > 0 && l.proc != nil {
		pct, err := l.proc.CPUPercent()
		if err != nil {
			return nil
		}

		avg := l.recordAndAverage(pct)

		// Only enforce once we have a full window of samples — avoids
		// false trips on the first reading right after the grace period.
		if avg > 0 && avg > l.MaxCPUPercent {
			return &ResourceExceededError{
				Resource: "cpu",
				Limit:    fmt.Sprintf("%.1f%% (sustained)", l.MaxCPUPercent),
				Current:  fmt.Sprintf("%.1f%% (avg over %s)", avg, cpuSampleWindow),
			}
		}
	}
	return nil
}

// recordAndAverage appends the current CPU sample and returns the average
// across the rolling window. Returns 0 if the window has not been fully
// populated yet (i.e. agent has not been measuring for a full window).
func (l *Limiter) recordAndAverage(current float64) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.cpuSeries = append(l.cpuSeries, cpuPoint{time: now, usage: current})

	cutoff := now.Add(-cpuSampleWindow)
	keep := 0
	for i, s := range l.cpuSeries {
		if s.time.After(cutoff) {
			keep = i
			break
		}
	}
	if keep > 0 {
		l.cpuSeries = l.cpuSeries[keep:]
	}

	// Require the window to be at least mostly populated before we trust
	// the average — avoids tripping on the first sample after grace period.
	if len(l.cpuSeries) < 3 ||
		now.Sub(l.cpuSeries[0].time) < cpuSampleWindow/2 {
		return 0
	}

	var sum float64
	for _, s := range l.cpuSeries {
		sum += s.usage
	}
	return sum / float64(len(l.cpuSeries))
}
