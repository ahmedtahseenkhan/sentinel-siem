package forwarder

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

const (
	// maxEventBufItems caps in-memory event buffer to prevent OOM on slow indexer.
	maxEventBufItems = 50_000
	// maxAlertBufItems caps in-memory alert buffer.
	maxAlertBufItems = 5_000
	// maxSendRetries is the number of times a batch is retried before DLQ.
	maxSendRetries = 3
	// dlqMaxItems is the maximum number of failed batches kept in the DLQ.
	dlqMaxItems = 100
)

// dlqBatch is a failed batch stored in the dead-letter queue.
type dlqBatch struct {
	kind   string // "events" or "alerts"
	events []*models.Event
	alerts []*models.Alert
}

type Forwarder struct {
	cfg       config.ForwarderConfig
	logger    *zap.Logger
	client    *Client
	eventBuf  []*models.Event
	alertBuf  []*models.Alert
	mu        sync.Mutex
	batchSize int
	stopCh    chan struct{}
	eventCh   chan *models.Event
	alertCh   chan *models.Alert

	// dead-letter queue for batches that fail after all retries
	dlqMu  sync.Mutex
	dlq    []dlqBatch

	// metrics
	droppedEvents int64
	droppedAlerts int64
	dlqDepth      int64
}

func New(cfg config.ForwarderConfig, logger *zap.Logger) *Forwarder {
	batchSize := cfg.WatchVault.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	return &Forwarder{
		cfg:       cfg,
		logger:    logger,
		batchSize: batchSize,
		stopCh:    make(chan struct{}),
		eventCh:   make(chan *models.Event, 10000),
		alertCh:   make(chan *models.Alert, 1000),
	}
}

func (f *Forwarder) Start(ctx context.Context) error {
	client, err := NewClient(f.cfg.WatchVault, f.logger)
	if err != nil {
		f.logger.Warn("forwarder: could not connect to WatchVault, will buffer events", zap.Error(err))
	}
	f.client = client

	interval, err := time.ParseDuration(f.cfg.WatchVault.FlushInterval)
	if err != nil || interval <= 0 {
		interval = 5 * time.Second
	}

	go f.runLoop(ctx, interval)
	return nil
}

func (f *Forwarder) ForwardEvent(event *models.Event) {
	select {
	case f.eventCh <- event:
	default:
		atomic.AddInt64(&f.droppedEvents, 1)
		f.logger.Warn("forwarder: event channel full, dropping event",
			zap.Int64("total_dropped", atomic.LoadInt64(&f.droppedEvents)))
	}
}

func (f *Forwarder) ForwardAlert(alert *models.Alert) {
	select {
	case f.alertCh <- alert:
	default:
		atomic.AddInt64(&f.droppedAlerts, 1)
		f.logger.Warn("forwarder: alert channel full, dropping alert",
			zap.Int64("total_dropped", atomic.LoadInt64(&f.droppedAlerts)))
	}
}

// Stats returns operational counters for monitoring.
func (f *Forwarder) Stats() (droppedEvents, droppedAlerts, dlqDepth int64) {
	return atomic.LoadInt64(&f.droppedEvents),
		atomic.LoadInt64(&f.droppedAlerts),
		atomic.LoadInt64(&f.dlqDepth)
}

func (f *Forwarder) runLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			f.flush()
			return
		case <-f.stopCh:
			f.flush()
			return
		case event := <-f.eventCh:
			f.mu.Lock()
			if len(f.eventBuf) < maxEventBufItems {
				f.eventBuf = append(f.eventBuf, event)
			} else {
				atomic.AddInt64(&f.droppedEvents, 1)
				f.logger.Warn("forwarder: event buffer cap reached, dropping event",
					zap.Int64("total_dropped", atomic.LoadInt64(&f.droppedEvents)))
			}
			shouldFlush := len(f.eventBuf) >= f.batchSize
			f.mu.Unlock()
			if shouldFlush {
				f.flush()
			}
		case alert := <-f.alertCh:
			f.mu.Lock()
			if len(f.alertBuf) < maxAlertBufItems {
				f.alertBuf = append(f.alertBuf, alert)
			} else {
				atomic.AddInt64(&f.droppedAlerts, 1)
				f.logger.Warn("forwarder: alert buffer cap reached, dropping alert",
					zap.Int64("total_dropped", atomic.LoadInt64(&f.droppedAlerts)))
			}
			f.mu.Unlock()
		case <-ticker.C:
			f.flush()
		}
	}
}

func (f *Forwarder) flush() {
	f.mu.Lock()
	events := f.eventBuf
	alerts := f.alertBuf
	f.eventBuf = nil
	f.alertBuf = nil
	f.mu.Unlock()

	if len(events) == 0 && len(alerts) == 0 {
		return
	}

	if f.client == nil {
		f.logger.Debug("forwarder: no client, discarding batch",
			zap.Int("events", len(events)),
			zap.Int("alerts", len(alerts)),
		)
		return
	}

	if len(events) > 0 {
		if err := f.sendWithRetry("events", func() error {
			return f.client.SendEvents(events)
		}); err != nil {
			f.enqueueDLQ(dlqBatch{kind: "events", events: events})
		} else {
			f.logger.Debug("forwarder: events sent", zap.Int("count", len(events)))
		}
	}

	if len(alerts) > 0 {
		if err := f.sendWithRetry("alerts", func() error {
			return f.client.SendAlerts(alerts)
		}); err != nil {
			f.enqueueDLQ(dlqBatch{kind: "alerts", alerts: alerts})
		} else {
			f.logger.Debug("forwarder: alerts sent", zap.Int("count", len(alerts)))
		}
	}
}

// sendWithRetry calls fn up to maxSendRetries times with exponential backoff.
func (f *Forwarder) sendWithRetry(kind string, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxSendRetries; attempt++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 500 * time.Millisecond
			f.logger.Warn("forwarder: send failed, retrying",
				zap.String("kind", kind),
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)
			time.Sleep(backoff)
		}
	}
	f.logger.Error("forwarder: all retries exhausted, sending to DLQ",
		zap.String("kind", kind),
		zap.Error(lastErr),
	)
	return lastErr
}

// enqueueDLQ stores a failed batch in the dead-letter queue.
// Oldest entries are evicted when the queue is full.
func (f *Forwarder) enqueueDLQ(batch dlqBatch) {
	f.dlqMu.Lock()
	defer f.dlqMu.Unlock()
	if len(f.dlq) >= dlqMaxItems {
		f.dlq = f.dlq[1:] // evict oldest
	}
	f.dlq = append(f.dlq, batch)
	atomic.StoreInt64(&f.dlqDepth, int64(len(f.dlq)))
	f.logger.Warn("forwarder: batch added to DLQ",
		zap.String("kind", batch.kind),
		zap.Int("dlq_depth", len(f.dlq)),
	)
}

// DLQDepth returns the current number of batches in the dead-letter queue.
func (f *Forwarder) DLQDepth() int {
	f.dlqMu.Lock()
	defer f.dlqMu.Unlock()
	return len(f.dlq)
}

func (f *Forwarder) Stop() {
	close(f.stopCh)
	if f.client != nil {
		f.client.Close()
	}
}

// Ingest implements the EventSink interface used by the gRPC handler.
func (f *Forwarder) Ingest(event *models.Event) {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	f.ForwardEvent(event)
}

func marshalEvent(e *models.Event) []byte {
	data, _ := json.Marshal(e.Fields)
	return data
}
