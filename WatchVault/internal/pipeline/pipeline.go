package pipeline

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/watchvault/watchvault/internal/config"
	"github.com/watchvault/watchvault/internal/models"
	"github.com/watchvault/watchvault/internal/opensearch"
	"go.uber.org/zap"
)

const (
	// maxBufferItems caps the in-memory bulk buffer to prevent OOM during spikes.
	maxBufferItems = 100_000
	// maxFlushRetries is the number of times a bulk flush is retried on error.
	maxFlushRetries = 3
)

type Pipeline struct {
	cfg          config.PipelineConfig
	indices      config.IndicesConfig
	logger       *zap.Logger
	client       *opensearch.Client
	buffer       []opensearch.BulkItem
	mu           sync.Mutex
	totalIndexed int64
	droppedItems int64
	stopCh       chan struct{}
}

func New(cfg config.PipelineConfig, indices config.IndicesConfig, client *opensearch.Client, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		cfg:     cfg,
		indices: indices,
		logger:  logger,
		client:  client,
		stopCh:  make(chan struct{}),
	}
}

func (p *Pipeline) Start() {
	interval, err := time.ParseDuration(p.cfg.FlushInterval)
	if err != nil || interval <= 0 {
		interval = 5 * time.Second
	}
	go p.flushLoop(interval)
	p.logger.Info("pipeline started",
		zap.Int("workers", p.cfg.Workers),
		zap.Int("bulk_size", p.cfg.BulkSize),
		zap.Duration("flush_interval", interval),
	)
}

func (p *Pipeline) ProcessEvent(event *models.IndexEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}

	indexName := p.routeEvent(event.EventType)
	doc := eventToDoc(event)

	return p.addToBuffer(opensearch.BulkItem{
		Index: indexName,
		ID:    event.ID,
		Doc:   doc,
	})
}

func (p *Pipeline) ProcessDocument(docType string, doc map[string]interface{}) error {
	indexName := p.indexName(docType)
	id := ""
	if v, ok := doc["id"].(string); ok {
		id = v
	} else {
		id = uuid.New().String()
	}

	// Ensure @timestamp is always present for OpenSearch time-based queries.
	if _, ok := doc["@timestamp"]; !ok {
		var tsMs int64
		switch v := doc["timestamp"].(type) {
		case int64:
			tsMs = v
		case float64:
			tsMs = int64(v)
		default:
			tsMs = time.Now().UnixMilli()
		}
		doc["@timestamp"] = time.UnixMilli(tsMs).UTC().Format(time.RFC3339Nano)
	}

	return p.addToBuffer(opensearch.BulkItem{
		Index: indexName,
		ID:    id,
		Doc:   doc,
	})
}

func (p *Pipeline) addToBuffer(item opensearch.BulkItem) error {
	p.mu.Lock()
	if len(p.buffer) >= maxBufferItems {
		p.mu.Unlock()
		atomic.AddInt64(&p.droppedItems, 1)
		p.logger.Warn("pipeline: buffer cap reached, dropping item",
			zap.String("index", item.Index),
			zap.Int64("total_dropped", atomic.LoadInt64(&p.droppedItems)),
		)
		return fmt.Errorf("pipeline buffer full: item dropped")
	}
	p.buffer = append(p.buffer, item)
	shouldFlush := len(p.buffer) >= p.cfg.BulkSize
	p.mu.Unlock()

	if shouldFlush {
		p.flush()
	}
	return nil
}

// DroppedItems returns the total number of items dropped due to buffer overflow.
func (p *Pipeline) DroppedItems() int64 {
	return atomic.LoadInt64(&p.droppedItems)
}

func (p *Pipeline) routeEvent(eventType string) string {
	switch {
	case eventType == "fim.added" || eventType == "fim.modified" || eventType == "fim.deleted":
		return p.indexName("fim")
	case eventType == "system.cpu" || eventType == "system.memory" || eventType == "system.disk" ||
		eventType == "system.network" || eventType == "system.process" || eventType == "system.host" ||
		eventType == "system.load" || eventType == "system.cpu.total":
		return p.indexName("system")
	case eventType == "vulnerability":
		return p.indexName("vulnerability")
	case eventType == "audit":
		return p.indexName("audit")
	default:
		return p.indexName("events")
	}
}

func (p *Pipeline) indexName(docType string) string {
	prefix := p.indices.Prefix
	if prefix == "" {
		prefix = "watchvault"
	}
	dateSuffix := time.Now().Format("2006.01.02")
	return fmt.Sprintf("%s-%s-%s", prefix, docType, dateSuffix)
}

func (p *Pipeline) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			p.flush()
			return
		case <-ticker.C:
			p.flush()
		}
	}
}

func (p *Pipeline) flush() {
	p.mu.Lock()
	items := p.buffer
	p.buffer = nil
	p.mu.Unlock()

	if len(items) == 0 {
		return
	}

	var lastErr error
	for attempt := 0; attempt < maxFlushRetries; attempt++ {
		indexed, err := p.client.BulkIndex(items)
		if err == nil {
			atomic.AddInt64(&p.totalIndexed, int64(indexed))
			p.logger.Debug("bulk indexed", zap.Int("count", indexed))
			return
		}
		lastErr = err
		backoff := time.Duration(math.Pow(2, float64(attempt))) * 500 * time.Millisecond
		p.logger.Warn("pipeline: bulk index failed, retrying",
			zap.Int("attempt", attempt+1),
			zap.Int("items", len(items)),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)
		time.Sleep(backoff)
	}
	p.logger.Error("pipeline: bulk index failed after all retries — items lost",
		zap.Int("items", len(items)),
		zap.Error(lastErr),
	)
	atomic.AddInt64(&p.droppedItems, int64(len(items)))
}

func (p *Pipeline) TotalIndexed() int64 {
	return atomic.LoadInt64(&p.totalIndexed)
}

func (p *Pipeline) Stop() {
	close(p.stopCh)
}

func eventToDoc(e *models.IndexEvent) map[string]interface{} {
	ts := e.Timestamp
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	doc := map[string]interface{}{
		"timestamp":   ts,
		"@timestamp":  time.UnixMilli(ts).UTC().Format(time.RFC3339Nano), // OpenSearch standard time field
		"event_type":  e.EventType,
		"agent_id":    e.AgentID,
		"agent_name":  e.AgentName,
	}
	if e.Data != nil {
		for k, v := range e.Data {
			doc[k] = v
		}
		// Promote common IP/identity fields to top level for Discover and dashboards
		normalizeEventFields(doc, e.Data)
	}
	if len(e.Tags) > 0 {
		doc["tags"] = e.Tags
	}
	return doc
}

// normalizeEventFields promotes nested IP and identity fields to top-level
// keyword fields so OpenSearch can search and aggregate on them directly.
func normalizeEventFields(doc map[string]interface{}, data map[string]interface{}) {
	// first returns the first meaningful value among the given keys. Windows
	// EventData uses a different field name for the "same" thing depending on the
	// event ID, so each canonical column is a fallback chain.
	first := func(keys ...string) string {
		for _, key := range keys {
			if v, ok := data[key].(string); ok {
				v = strings.TrimSpace(v)
				if v != "" && v != "-" && v != "0.0.0.0" && v != "::" && v != "::1" {
					return v
				}
			}
		}
		return ""
	}

	// Source / destination IP:
	//   network conn collector: raddr/laddr
	//   Windows logon 4624/4625: IpAddress
	//   Sysmon EID 3 (network): SourceIp / DestinationIp
	if ip := first("raddr", "win_IpAddress", "win_SourceIp", "win_SourceAddress", "src_ip", "source_ip", "srcip"); ip != "" {
		doc["src_ip"] = ip
	}
	if ip := first("laddr", "win_DestinationIp", "win_DestAddress", "dst_ip", "dstip"); ip != "" {
		doc["dst_ip"] = ip
	}

	// Username:
	//   logon 4624/4625: TargetUserName ; process 4688 / most: SubjectUserName
	//   Sysmon: User ; generic collectors: user/username
	if u := first("win_TargetUserName", "win_SubjectUserName", "win_User", "User", "user", "username"); u != "" {
		doc["username"] = u
	}

	// Process:
	//   4688 process creation: NewProcessName ; Sysmon EID 1: Image
	//   generic process collector: name
	if p := first("win_NewProcessName", "win_Image", "Image", "win_ProcessName", "name", "process_name"); p != "" {
		doc["process_name"] = p
		base := p
		if i := strings.LastIndexAny(p, `\/`); i >= 0 && i+1 < len(p) {
			base = p[i+1:]
		}
		doc["process"] = base // clean basename for display
	}

	// Command line (4688 with cmdline auditing, or Sysmon)
	if c := first("win_CommandLine", "win_ProcessCommandLine", "CommandLine", "command_line"); c != "" {
		doc["command_line"] = c
	}
}
