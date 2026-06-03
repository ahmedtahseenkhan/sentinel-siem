// Package canary implements ransomware canary (decoy file) monitoring.
//
// The collector plants fake-but-enticing files in watched directories and emits
// a critical "ransomware.canary" event the instant one is modified, renamed, or
// deleted. Legitimate users have no reason to touch these files, so a change is
// a high-confidence early signal of mass file encryption. The event flows to the
// WatchTower rule engine (rule 8100, MITRE T1486) like any other detection, so
// operators can attach an isolate-host playbook for automated containment.
package canary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "ransomware_canary"

// canaryNames are the decoy file names planted in each watched directory. They
// sort early (a directory-walking encryptor reaches them first) and look
// valuable, so real users leave them alone but ransomware encrypts them.
var canaryNames = []string{
	"0_Finance_Backup.xlsx",
	"0_Passwords.docx",
	"0_Customer_Records.pdf",
	"aaa_DO_NOT_DELETE.docx",
}

const canaryBanner = "SENTINEL SIEM ransomware canary — do not delete or modify. " +
	"If this file changes, the agent raises a ransomware alert.\n"

const fireCooldown = 30 * time.Second

type state struct {
	size int64
	hash string
}

// Collector implements models.Collector.
type Collector struct {
	cfg      agent.CanaryCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	watcher  *fsnotify.Watcher
	wg       sync.WaitGroup
	mu       sync.Mutex
	canaries map[string]state     // canary path -> baseline
	fired    map[string]time.Time // canary path -> last alert (cooldown)
}

func New(cfg agent.CanaryCollectorConfig) *Collector {
	return &Collector{
		cfg:      cfg,
		interval: agent.ParseDuration(cfg.Interval, 10*time.Second),
		dataCh:   make(chan models.DataPoint, 64),
		stopCh:   make(chan struct{}),
		canaries: make(map[string]state),
		fired:    make(map[string]time.Time),
	}
}

func (c *Collector) Name() string                      { return CollectorName }
func (c *Collector) Interval() time.Duration           { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) Start(ctx context.Context) error {
	c.plantAll()

	// fsnotify gives near-instant detection; the poll loop is a fallback for
	// platforms/filesystems where events are unreliable.
	if w, err := fsnotify.NewWatcher(); err == nil {
		c.watcher = w
		c.mu.Lock()
		dirs := map[string]bool{}
		for p := range c.canaries {
			dirs[filepath.Dir(p)] = true
		}
		c.mu.Unlock()
		for d := range dirs {
			_ = w.Add(d)
		}
		c.wg.Add(1)
		go c.watchLoop()
	}

	c.wg.Add(1)
	go c.pollLoop(ctx)
	return nil
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	if c.watcher != nil {
		_ = c.watcher.Close()
	}
	c.wg.Wait()
	return nil
}

func (c *Collector) numFiles() int {
	n := c.cfg.FileCount
	if n <= 0 || n > len(canaryNames) {
		n = 2
	}
	return n
}

// plantAll writes the decoy files and records their baseline. Safe to call
// repeatedly. Directories that don't exist are skipped (we never create user
// folders).
func (c *Collector) plantAll() {
	n := c.numFiles()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, dir := range c.cfg.Paths {
		if dir == "" {
			continue
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		for i := 0; i < n; i++ {
			p := filepath.Join(dir, canaryNames[i])
			if err := writeCanary(p); err != nil {
				continue
			}
			if st, ok := statOf(p); ok {
				c.canaries[p] = st
			}
		}
	}
}

func writeCanary(path string) error {
	content := canaryBanner + "\n" + strings.Repeat("Sentinel canary padding block. ", 64)
	return os.WriteFile(path, []byte(content), 0o644)
}

func statOf(path string) (state, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return state{}, false
	}
	sum := sha256.Sum256(b)
	return state{size: int64(len(b)), hash: hex.EncodeToString(sum[:])}, true
}

func (c *Collector) pollLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-t.C:
			c.checkAll()
		}
	}
}

func (c *Collector) checkAll() {
	c.mu.Lock()
	paths := make([]string, 0, len(c.canaries))
	for p := range c.canaries {
		paths = append(paths, p)
	}
	c.mu.Unlock()
	for _, p := range paths {
		c.evaluate(p)
	}
}

func (c *Collector) watchLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopCh:
			return
		case ev, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			c.mu.Lock()
			_, tracked := c.canaries[ev.Name]
			c.mu.Unlock()
			if tracked && ev.Op&(fsnotify.Write|fsnotify.Remove|fsnotify.Rename|fsnotify.Create) != 0 {
				c.evaluate(ev.Name)
			}
		case _, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
		}
	}
}

// evaluate compares a canary against its baseline and fires (once per cooldown)
// if it was modified or removed, then re-plants it so detection continues.
func (c *Collector) evaluate(path string) {
	c.mu.Lock()
	base, known := c.canaries[path]
	c.mu.Unlock()
	if !known {
		return
	}

	cur, ok := statOf(path)
	switch {
	case !ok:
		c.tamper(path, "deleted")
		c.replant(path)
	case cur.hash != base.hash || cur.size != base.size:
		c.tamper(path, "modified")
		c.replant(path)
	}
}

func (c *Collector) replant(path string) {
	if err := writeCanary(path); err != nil {
		return
	}
	if st, ok := statOf(path); ok {
		c.mu.Lock()
		c.canaries[path] = st // update baseline so our own re-write isn't a false hit
		c.mu.Unlock()
	}
}

func (c *Collector) tamper(path, change string) {
	c.mu.Lock()
	if time.Since(c.fired[path]) < fireCooldown {
		c.mu.Unlock()
		return
	}
	c.fired[path] = time.Now()
	c.mu.Unlock()

	fields := map[string]interface{}{
		"canary_path": path,
		"change":      change,
		"directory":   filepath.Dir(path),
		"message": fmt.Sprintf("Ransomware canary %s: %s — likely mass file encryption in progress",
			change, path),
	}
	select {
	case c.dataCh <- models.DataPoint{
		Timestamp: time.Now(),
		Type:      "ransomware.canary",
		Fields:    fields,
		Tags: map[string]string{
			"category": "ransomware",
			"severity": "critical",
		},
	}:
	default:
	}
}
