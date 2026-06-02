package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/internal/queue"
	"github.com/watchnode/watchnode/internal/resource"
	"github.com/watchnode/watchnode/internal/utils"
	"go.uber.org/zap"
)

func osHostname() (string, error) {
	return os.Hostname()
}

// ProductName is the public product name for WatchNode.
const ProductName = "WatchNode"

const Version = "1.0.0"

// Agent is the main orchestrator: loads config, runs collectors, and sends data to the manager.
type Agent struct {
	Config     *Config
	Logger     Logger
	Info       *models.AgentInfo
	collectors []models.Collector
	limiter    *resource.Limiter
	comm       ManagerClient
	dataCh     chan models.DataPoint
	diskQueue  *queue.DiskQueue
	stopCh     chan struct{}
	runCtx     context.Context
	cancel     context.CancelFunc
	warnMu     sync.Mutex
	lastWarnAt time.Time
	wg         sync.WaitGroup
	configMu   sync.RWMutex // guards live Config updates pushed from manager
	droppedPts int64        // total data points dropped due to full channel
	hostIPs    []string     // non-loopback IPv4 addresses discovered at startup
}

// ManagerClient is the interface for sending data and receiving commands from the manager.
type ManagerClient interface {
	Connect(ctx context.Context) error
	Register(ctx context.Context, info *models.AgentInfo) error
	SendBatch(ctx context.Context, agentID string, points []models.DataPoint) error
	RunHeartbeat(ctx context.Context, agentID string, interval time.Duration)
	RunStream(ctx context.Context, agentID string, dataCh <-chan models.DataPoint) error
	SetCommandHandler(handler func(commandType string, payload []byte))
	Close() error
}

// New creates an Agent from config and dependencies.
func New(cfg *Config, log Logger, comm ManagerClient) (*Agent, error) {
	hostname, _ := osHostname()
	agentName := cfg.Agent.Name
	if agentName == "" || agentName == "{{hostname}}" {
		agentName = hostname
	}
	info := &models.AgentInfo{
		Version:   Version,
		Hostname:  hostname,
		OS:        utils.OS(),
		Platform:  utils.Platform(),
		Labels:    cfg.Agent.Labels,
		StartTime: time.Now(),
	}
	if cfg.Agent.ID != "" {
		info.ID = cfg.Agent.ID
	}
	return &Agent{
		Config:     cfg,
		Logger:     log,
		Info:       info,
		limiter:    resource.NewLimiter(cfg.Performance.MaxCPUPercent, cfg.Performance.MaxMemoryBytes, cfg.Performance.MaxDiskBytes),
		comm:       comm,
		dataCh:     make(chan models.DataPoint, cfg.Performance.QueueSize),
		stopCh:     make(chan struct{}),
		collectors: nil,
		hostIPs:    discoverHostIPs(),
	}, nil
}

// discoverHostIPs returns the first non-loopback, non-link-local IPv4 address
// on each active interface. Called once at startup and cached.
func discoverHostIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				ips = append(ips, ipv4.String())
			}
		}
	}
	return ips
}

// enrichPoint injects agent-level metadata into every outbound DataPoint.
// This ensures every event reaching OpenSearch carries agent_id, hostname,
// version, OS, and IP — regardless of which collector emitted it.
func (a *Agent) enrichPoint(p *models.DataPoint) {
	if p.Tags == nil {
		p.Tags = make(map[string]string, 6)
	}
	p.Tags["agent_id"] = a.Info.ID
	p.Tags["agent_version"] = a.Info.Version
	p.Tags["host_hostname"] = a.Info.Hostname
	p.Tags["host_os"] = a.Info.OS
	if len(a.hostIPs) > 0 {
		p.Tags["host_ip"] = a.hostIPs[0]
	}
}

// LoadAgentID loads or creates the agent ID and sets it on Info.
func (a *Agent) LoadAgentID(configDir string) error {
	path := utils.AgentIDPath(configDir)
	// Seed with the hostname so a lost/ephemeral persist file regenerates the
	// SAME id (stable per machine; no ghost agents on reinstall/container restart).
	id, err := utils.LoadOrCreateAgentID(path, a.Info.Hostname)
	if err != nil {
		return err
	}
	a.Info.ID = id
	a.Logger.Info("agent id loaded", zap.String("agent_id", id))
	return nil
}

// SetCollectors registers the collectors to run. Call before Start.
func (a *Agent) SetCollectors(collectors []models.Collector) {
	a.collectors = collectors
}

// Start starts all collectors and the communication layer.
func (a *Agent) Start(ctx context.Context) error {
	a.runCtx, a.cancel = context.WithCancel(ctx)
	if a.Info.ID == "" {
		if err := a.LoadAgentID(""); err != nil {
			a.Logger.Warn("agent id not loaded, deriving stable id from hostname", zap.Error(err))
			a.Info.ID = utils.StableAgentID(a.Info.Hostname)
		}
	}

	// Initialise disk-backed queue when enabled.
	var streamCh <-chan models.DataPoint = a.dataCh
	if a.Config.Performance.DiskQueue.Enabled {
		dir := a.Config.Performance.DiskQueue.Dir
		if dir == "" {
			dir = defaultQueueDir()
		}
		dq, err := queue.NewDiskQueue(dir, a.Config.Performance.DiskQueue.MaxBytes)
		if err != nil {
			a.Logger.Warn("disk queue init failed, falling back to RAM queue", zap.Error(err))
		} else {
			a.diskQueue = dq
			dq.Start(a.runCtx)
			streamCh = dq.Output()
			a.Logger.Info("disk queue enabled", zap.String("dir", dir))
		}
	}

	if err := a.comm.Connect(a.runCtx); err != nil {
		return err
	}

	if err := a.comm.Register(a.runCtx, a.Info); err != nil {
		a.Logger.Warn("agent registration failed", zap.Error(err))
	}

	a.comm.SetCommandHandler(a.handleManagerCommand)

	for _, c := range a.collectors {
		a.wg.Add(1)
		go func(c models.Collector) {
			defer a.wg.Done()
			if err := c.Start(a.runCtx); err != nil {
				a.Logger.Error("collector failed", zap.String("collector", c.Name()), zap.Error(err))
				return
			}
		}(c)
	}

	a.wg.Add(1)
	go a.fanIn()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.comm.RunStream(a.runCtx, a.Info.ID, streamCh); err != nil {
			a.Logger.Warn("stream exited", zap.Error(err))
		}
	}()

	interval := ParseDuration(a.Config.Performance.FlushInterval, 30*time.Second)
	a.wg.Add(1)
	go a.runHeartbeat(interval)

	a.wg.Add(1)
	go a.runHealthMonitor()

	a.Logger.Info("agent started",
		zap.String("product", ProductName),
		zap.String("agent_id", a.Info.ID),
		zap.String("version", a.Info.Version),
		zap.Strings("host_ips", a.hostIPs),
	)
	return nil
}

// defaultQueueDir returns the OS-appropriate data directory for the disk queue.
func defaultQueueDir() string {
	// Windows: C:\ProgramData\SentinelAgent\queue
	// Linux/macOS: /var/lib/watchnode/queue or ./queue
	if dir := os.Getenv("WATCHNODE_QUEUE_DIR"); dir != "" {
		return dir
	}
	if _, err := os.Stat("/var/lib"); err == nil {
		return "/var/lib/watchnode/queue"
	}
	return "queue"
}

// Stop stops all collectors and the communication layer gracefully.
// Goroutines are given up to 15 seconds to finish; after that they are
// abandoned so the process can exit cleanly.
func (a *Agent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	close(a.stopCh)
	for _, c := range a.collectors {
		c.Stop()
	}
	close(a.dataCh)
	_ = a.comm.Close()
	if a.diskQueue != nil {
		_ = a.diskQueue.Close()
	}

	// Wait with a hard deadline so a stuck goroutine never blocks shutdown.
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		a.Logger.Info("agent stopped cleanly")
	case <-time.After(15 * time.Second):
		a.Logger.Warn("agent stop timed out — forcing exit")
	}
}

func (a *Agent) fanIn() {
	defer a.wg.Done()
	for _, c := range a.collectors {
		ch := c.DataChan()
		if ch == nil {
			continue
		}
		a.wg.Add(1)
		go func(src <-chan models.DataPoint) {
			defer a.wg.Done()
			for {
				select {
				case <-a.stopCh:
					return
				case p, ok := <-src:
					if !ok {
						return
					}
					// Inject agent identity + host context into every event.
					a.enrichPoint(&p)

					// Resource limits throttle the SENDER (RunStream),
					// never the collector. Data is always persisted to
					// the disk queue first — only drop if disk queue is
					// full and the RAM fallback is also full.
					if a.diskQueue != nil {
						if err := a.diskQueue.Write(p); err == nil {
							continue
						} else {
							a.throttledWarn("disk queue write failed, using RAM", err, 30*time.Second)
						}
					}
					select {
					case a.dataCh <- p:
					default:
						dropped := atomic.AddInt64(&a.droppedPts, 1)
						a.throttledWarn(
							"data channel full, dropping point",
							fmt.Errorf("type=%s total_dropped=%d", p.Type, dropped),
							5*time.Second,
						)
					}
				}
			}
		}(ch)
	}
	// Wait for stop; fanIn never closes dataCh so RunStream can drain it.
	<-a.stopCh
}

func (a *Agent) runHeartbeat(interval time.Duration) {
	defer a.wg.Done()
	a.comm.RunHeartbeat(a.runCtx, a.Info.ID, interval)
}

// runHealthMonitor periodically samples the resource limiter and logs a
// warning when sustained usage exceeds configured limits. It NEVER drops
// data — telemetry persistence is handled by the disk queue and the limiter
// is purely an observability signal.
func (a *Agent) runHealthMonitor() {
	defer a.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.limiter.Check(); err != nil {
				a.throttledWarn("agent health: sustained resource usage", err, 5*time.Minute)
			}
		}
	}
}

func (a *Agent) throttledWarn(msg string, err error, minInterval time.Duration) {
	a.warnMu.Lock()
	defer a.warnMu.Unlock()
	now := time.Now()
	if !a.lastWarnAt.IsZero() && now.Sub(a.lastWarnAt) < minInterval {
		return
	}
	a.lastWarnAt = now
	a.Logger.Warn(msg, zap.Error(err))
}
