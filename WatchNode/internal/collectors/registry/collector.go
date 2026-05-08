package registry

import (
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "registry"

// Collector monitors Windows Registry keys for changes.
// On non-Windows platforms this is a no-op.
type Collector struct {
	cfg      agent.RegistryCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
	baseline map[string]map[string]string // keyPath -> valueName -> data
}

// New creates a registry monitoring collector.
func New(cfg agent.RegistryCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 5*time.Minute)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 128),
		stopCh:   make(chan struct{}),
		baseline: make(map[string]map[string]string),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}
