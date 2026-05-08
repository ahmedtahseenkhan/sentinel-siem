package osquery

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "osquery"

// Collector integrates with osquery to run scheduled queries.
type Collector struct {
	cfg      agent.OsqueryCollectorConfig
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// New creates an osquery integration collector.
func New(cfg agent.OsqueryCollectorConfig) *Collector {
	return &Collector{
		cfg:    cfg,
		dataCh: make(chan models.DataPoint, 256),
		stopCh: make(chan struct{}),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return 60 * time.Second }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
	if !c.isOsqueryAvailable() {
		// If osquery is not installed, just block
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		}
	}

	// Run each query on its own schedule
	for _, q := range c.cfg.Queries {
		c.wg.Add(1)
		go c.runQueryLoop(ctx, q)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return nil
	}
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	c.wg.Wait()
	return nil
}

func (c *Collector) isOsqueryAvailable() bool {
	binaryPath := c.cfg.BinaryPath
	if binaryPath == "" {
		binaryPath = "osqueryi"
	}
	_, err := exec.LookPath(binaryPath)
	return err == nil
}

func (c *Collector) runQueryLoop(ctx context.Context, q agent.OsqueryQuery) {
	defer c.wg.Done()
	interval := agent.ParseDuration(q.Interval, 5*time.Minute)
	
	// Run immediately
	c.executeQuery(q)
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.executeQuery(q)
		}
	}
}

func (c *Collector) executeQuery(q agent.OsqueryQuery) {
	binaryPath := c.cfg.BinaryPath
	if binaryPath == "" {
		binaryPath = "osqueryi"
	}
	
	// Run osqueryi with JSON output
	cmd := exec.Command(binaryPath, "--json", q.Query)
	out, err := cmd.Output()
	if err != nil {
		return
	}

	ts := time.Now()
	
	// Try parsing as JSON array
	var results []map[string]interface{}
	if err := json.Unmarshal(out, &results); err == nil {
		for _, row := range results {
			fields := map[string]interface{}{
				"query_name": q.Name,
				"query":      q.Query,
			}
			for k, v := range row {
				fields[k] = v
			}
			c.emit(ts, "osquery.result", fields, map[string]string{
				"query_name": q.Name,
			})
		}
		return
	}

	// Fallback: emit raw output line by line
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		c.emit(ts, "osquery.result", map[string]interface{}{
			"query_name": q.Name,
			"query":      q.Query,
			"raw_output": line,
		}, map[string]string{
			"query_name": q.Name,
		})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// Ensure os package is used (for potential future file operations).
func init() {
	_ = os.DevNull
}
