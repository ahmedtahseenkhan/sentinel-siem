package logs

import (
	"context"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "logs"

// Collector tails log files and optionally journald/eventlog.
type Collector struct {
	cfg     agent.LogsCollectorConfig
	dataCh  chan models.DataPoint
	stopCh  chan struct{}
	tailers []*tailer
	wg      sync.WaitGroup
}

// New creates a log collector.
func New(cfg agent.LogsCollectorConfig) *Collector {
	return &Collector{
		cfg:    cfg,
		dataCh: make(chan models.DataPoint, 512),
		stopCh: make(chan struct{}),
	}
}

// Name implements models.Collector.
func (c *Collector) Name() string { return CollectorName }

// Interval implements models.Collector (logs are continuous).
func (c *Collector) Interval() time.Duration { return 0 }

// DataChan implements models.Collector.
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

// Start implements models.Collector.
func (c *Collector) Start(ctx context.Context) error {
	maxLine := c.cfg.MaxLineLength
	if maxLine <= 0 {
		maxLine = 1048576
	}
	maxBuf := c.cfg.MaxBufferSize
	if maxBuf <= 0 {
		maxBuf = 10485760
	}
	for _, src := range c.cfg.Sources {
		switch src.Type {
		case "file":
			t := newTailer(src.Path, src.Tags, src.MultilinePattern, maxLine, maxBuf)
			c.tailers = append(c.tailers, t)
			c.wg.Add(1)
			go func(t *tailer) {
				defer c.wg.Done()
				t.run(ctx, c.dataCh, c.stopCh)
			}(t)
		case "journal":
			c.wg.Add(1)
			go func(units []string) {
				defer c.wg.Done()
				runJournal(ctx, units, c.dataCh, c.stopCh)
			}(src.Units)
		case "eventlog":
			c.wg.Add(1)
			go func(channels []string) {
				defer c.wg.Done()
				runEventLog(ctx, channels, c.dataCh, c.stopCh)
			}(src.Channels)
		}
	}
	return nil
}

// Stop implements models.Collector.
func (c *Collector) Stop() error {
	close(c.stopCh)
	for _, t := range c.tailers {
		t.close()
	}
	c.wg.Wait()
	return nil
}
