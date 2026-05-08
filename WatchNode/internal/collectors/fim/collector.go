package fim

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/internal/utils"
)

const CollectorName = "file_integrity"

// Collector monitors file system changes and emits FIM events.
type Collector struct {
	cfg      agent.FileIntegrityCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	watcher  *fsnotify.Watcher
	mu       sync.Mutex
	wg       sync.WaitGroup
	baseline map[string]string // path -> sha256
	permMap  map[string]uint32 // path -> permissions mask
}

// New creates a file integrity monitoring collector.
func New(cfg agent.FileIntegrityCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 5*time.Minute)
	return &Collector{
		cfg:     cfg,
		interval: interval,
		dataCh:  make(chan models.DataPoint, 256),
		stopCh:  make(chan struct{}),
		baseline: make(map[string]string),
		permMap:  make(map[string]uint32),
	}
}

// Name implements models.Collector.
func (c *Collector) Name() string { return CollectorName }

// Interval implements models.Collector.
func (c *Collector) Interval() time.Duration { return c.interval }

// DataChan implements models.Collector.
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

// Start implements models.Collector.
func (c *Collector) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	c.watcher = watcher

	if c.cfg.ScanOnStart {
		c.runBaselineScan()
	}

	for _, p := range c.cfg.Paths {
		if p.Recursive {
			_ = filepath.Walk(p.Path, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil || !info.IsDir() {
					return nil
				}
				if c.ignorePath(path, p.IgnorePatterns) {
					return filepath.SkipDir
				}
				_ = c.watcher.Add(path)
				return nil
			})
		} else {
			_ = c.watcher.Add(p.Path)
		}
	}

	c.wg.Add(1)
	go c.runWatch(ctx)
	return nil
}

func (c *Collector) ignorePath(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, p := range patterns {
		ok, _ := filepath.Match(p, base)
		if ok {
			return true
		}
	}
	return false
}

func (c *Collector) runBaselineScan() {
	for _, p := range c.cfg.Paths {
		_ = filepath.Walk(p.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if c.ignorePath(path, p.IgnorePatterns) {
				return nil
			}
			hash, err := utils.SHA256File(path)
			if err != nil {
				return nil
			}
			c.mu.Lock()
			c.baseline[path] = hash
			c.permMap[path] = uint32(info.Mode().Perm())
			c.mu.Unlock()
			return nil
		})
	}
}

func (c *Collector) runWatch(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case ev, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			c.handleEvent(ev)
		case <-ticker.C:
			c.runIncrementalScan()
		}
	}
}

func (c *Collector) handleEvent(ev fsnotify.Event) {
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Chmod) == 0 {
		return
	}
	ts := time.Now()
	path := ev.Name
	c.mu.Lock()
	oldHash := c.baseline[path]
	oldPerm := c.permMap[path]
	c.mu.Unlock()

	switch {
	case ev.Op&fsnotify.Remove != 0:
		c.emit(ts, "fim.deleted", map[string]interface{}{"path": path, "previous_hash": oldHash}, map[string]string{"path": path})
		c.mu.Lock()
		delete(c.baseline, path)
		delete(c.permMap, path)
		c.mu.Unlock()
	case ev.Op&fsnotify.Chmod != 0:
		st, err := os.Stat(path)
		if err != nil {
			c.emit(ts, "fim.permission_changed", map[string]interface{}{"path": path, "error": err.Error()}, map[string]string{"path": path})
			return
		}
		newPerm := uint32(st.Mode().Perm())
		if newPerm != oldPerm {
			c.emit(ts, "fim.permission_changed", map[string]interface{}{
				"path":                 path,
				"previous_permissions": oldPerm,
				"permissions":          newPerm,
			}, map[string]string{"path": path})
		}
		c.mu.Lock()
		c.permMap[path] = newPerm
		c.mu.Unlock()
	case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
		hash, err := utils.SHA256File(path)
		if err != nil {
			c.emit(ts, "fim.modified", map[string]interface{}{"path": path, "error": err.Error()}, map[string]string{"path": path})
			return
		}
		op := "modified"
		if ev.Op&fsnotify.Create != 0 {
			op = "added"
		}
		fields := map[string]interface{}{"path": path, "sha256": hash, "previous_hash": oldHash}
		if st, err := os.Stat(path); err == nil {
			fields["permissions"] = uint32(st.Mode().Perm())
		}
		c.emit(ts, "fim."+op, fields, map[string]string{"path": path})
		c.mu.Lock()
		c.baseline[path] = hash
		if st, err := os.Stat(path); err == nil {
			c.permMap[path] = uint32(st.Mode().Perm())
		}
		c.mu.Unlock()
	}
}

func (c *Collector) runIncrementalScan() {
	for _, p := range c.cfg.Paths {
		_ = filepath.Walk(p.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if c.ignorePath(path, p.IgnorePatterns) {
				return nil
			}
			hash, err := utils.SHA256File(path)
			if err != nil {
				return nil
			}
			c.mu.Lock()
			old, ok := c.baseline[path]
			oldPerm := c.permMap[path]
			c.mu.Unlock()
			if ok && old != hash {
				ts := time.Now()
				c.emit(ts, "fim.modified", map[string]interface{}{"path": path, "sha256": hash, "previous_hash": old}, map[string]string{"path": path})
			}
			newPerm := uint32(info.Mode().Perm())
			if ok && oldPerm != 0 && oldPerm != newPerm {
				ts := time.Now()
				c.emit(ts, "fim.permission_changed", map[string]interface{}{
					"path":                 path,
					"previous_permissions": oldPerm,
					"permissions":          newPerm,
				}, map[string]string{"path": path})
			}
			if !ok {
				c.mu.Lock()
				c.baseline[path] = hash
				c.permMap[path] = newPerm
				c.mu.Unlock()
			} else {
				c.mu.Lock()
				c.permMap[path] = newPerm
				c.mu.Unlock()
			}
			return nil
		})
	}
}

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// Stop implements models.Collector.
func (c *Collector) Stop() error {
	close(c.stopCh)
	if c.watcher != nil {
		_ = c.watcher.Close()
	}
	c.wg.Wait()
	return nil
}
