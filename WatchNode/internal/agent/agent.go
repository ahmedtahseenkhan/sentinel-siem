package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/watchnode/watchnode/internal/models"
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
	stopCh     chan struct{}
	runCtx     context.Context
	cancel     context.CancelFunc
	warnMu     sync.Mutex
	lastWarnAt time.Time
	wg         sync.WaitGroup
	configMu   sync.RWMutex // guards live Config updates pushed from manager
	droppedPts int64        // total data points dropped due to full channel
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
		Config:    cfg,
		Logger:    log,
		Info:      info,
		limiter:   resource.NewLimiter(cfg.Performance.MaxCPUPercent, cfg.Performance.MaxMemoryBytes, cfg.Performance.MaxDiskBytes),
		comm:      comm,
		dataCh:    make(chan models.DataPoint, cfg.Performance.QueueSize),
		stopCh:    make(chan struct{}),
		collectors: nil,
	}, nil
}

// LoadAgentID loads or creates the agent ID and sets it on Info.
func (a *Agent) LoadAgentID(configDir string) error {
	path := utils.AgentIDPath(configDir)
	id, err := utils.LoadOrCreateAgentID(path)
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
			a.Logger.Warn("agent id not loaded, using ephemeral id", zap.Error(err))
			a.Info.ID, _ = utils.GenerateAgentID()
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
		if err := a.comm.RunStream(a.runCtx, a.Info.ID, a.dataCh); err != nil {
			a.Logger.Warn("stream exited", zap.Error(err))
		}
	}()

	interval := ParseDuration(a.Config.Performance.FlushInterval, 30*time.Second)
	a.wg.Add(1)
	go a.runHeartbeat(interval)

	a.Logger.Info("agent started", zap.String("product", ProductName), zap.String("agent_id", a.Info.ID), zap.String("version", a.Info.Version))
	return nil
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
					if err := a.limiter.Check(); err != nil {
						a.throttledWarn("resource limit exceeded, dropping point", err, 10*time.Second)
						continue
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
	// Wait for stop to close dataCh; fanIn doesn't close it so RunStream can drain
	<-a.stopCh
}

func (a *Agent) runHeartbeat(interval time.Duration) {
	defer a.wg.Done()
	a.comm.RunHeartbeat(a.runCtx, a.Info.ID, interval)
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
