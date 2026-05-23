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
	"github.com/watchnode/watchnode/internal/whodata"
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
	ownerMap map[string]uint32 // path -> uid
	groupMap map[string]uint32 // path -> gid
}

// New creates a file integrity monitoring collector.
func New(cfg agent.FileIntegrityCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 5*time.Minute)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 256),
		stopCh:   make(chan struct{}),
		baseline: make(map[string]string),
		permMap:  make(map[string]uint32),
		ownerMap: make(map[string]uint32),
		groupMap: make(map[string]uint32),
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

	// Drop the configured FIM paths into the helper file so the audit
	// collector (Linux) can auto-install `auditctl -w` rules and the
	// FIM events that follow can be attributed to a user.
	if c.cfg.Whodata {
		c.writeWhodataPathsFile()
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
			_, _, sha256sum, err := utils.FileHashes(path)
			if err != nil {
				return nil
			}
			uid, gid := fileOwner(info)
			c.mu.Lock()
			c.baseline[path] = sha256sum
			c.permMap[path] = uint32(info.Mode().Perm())
			c.ownerMap[path] = uid
			c.groupMap[path] = gid
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
	oldOwner := c.ownerMap[path]
	oldGroup := c.groupMap[path]
	c.mu.Unlock()

	switch {
	case ev.Op&fsnotify.Remove != 0:
		c.emit(ts, "fim.deleted", map[string]interface{}{"path": path, "previous_hash": oldHash}, map[string]string{"path": path})
		c.mu.Lock()
		delete(c.baseline, path)
		delete(c.permMap, path)
		delete(c.ownerMap, path)
		delete(c.groupMap, path)
		c.mu.Unlock()
	case ev.Op&fsnotify.Chmod != 0:
		st, err := os.Stat(path)
		if err != nil {
			c.emit(ts, "fim.permission_changed", map[string]interface{}{"path": path, "error": err.Error()}, map[string]string{"path": path})
			return
		}
		newPerm := uint32(st.Mode().Perm())
		newOwner, newGroup := fileOwner(st)
		fields := map[string]interface{}{
			"path":                 path,
			"previous_permissions": oldPerm,
			"permissions":          newPerm,
		}
		if newOwner != oldOwner || newGroup != oldGroup {
			fields["previous_owner"] = oldOwner
			fields["owner"] = newOwner
			fields["previous_group"] = oldGroup
			fields["group"] = newGroup
		}
		if newPerm != oldPerm || newOwner != oldOwner || newGroup != oldGroup {
			c.emit(ts, "fim.permission_changed", fields, map[string]string{"path": path})
		}
		c.mu.Lock()
		c.permMap[path] = newPerm
		c.ownerMap[path] = newOwner
		c.groupMap[path] = newGroup
		c.mu.Unlock()
	case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
		md5sum, sha1sum, sha256sum, err := utils.FileHashes(path)
		if err != nil {
			c.emit(ts, "fim.modified", map[string]interface{}{"path": path, "error": err.Error()}, map[string]string{"path": path})
			return
		}
		op := "modified"
		if ev.Op&fsnotify.Create != 0 {
			op = "added"
		}
		fields := map[string]interface{}{
			"path":          path,
			"md5":           md5sum,
			"sha1":          sha1sum,
			"sha256":        sha256sum,
			"previous_hash": oldHash,
		}
		if st, err := os.Stat(path); err == nil {
			fields["permissions"] = uint32(st.Mode().Perm())
			uid, gid := fileOwner(st)
			fields["owner"] = uid
			fields["group"] = gid
			c.mu.Lock()
			c.permMap[path] = uint32(st.Mode().Perm())
			c.ownerMap[path] = uid
			c.groupMap[path] = gid
			c.mu.Unlock()
		}
		c.emit(ts, "fim."+op, fields, map[string]string{"path": path})
		c.mu.Lock()
		c.baseline[path] = sha256sum
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
			md5sum, sha1sum, sha256sum, err := utils.FileHashes(path)
			if err != nil {
				return nil
			}
			c.mu.Lock()
			old, ok := c.baseline[path]
			oldPerm := c.permMap[path]
			c.mu.Unlock()
			if ok && old != sha256sum {
				ts := time.Now()
				c.emit(ts, "fim.modified", map[string]interface{}{
					"path":          path,
					"md5":           md5sum,
					"sha1":          sha1sum,
					"sha256":        sha256sum,
					"previous_hash": old,
				}, map[string]string{"path": path})
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
				c.baseline[path] = sha256sum
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
	// Whodata enrichment: if an audit / 4663 event for this path arrived
	// within the cache TTL, attach the user attribution before emitting.
	// Lookup is cheap (one map probe under a mutex) and a miss is fine —
	// the field simply isn't added.
	if path, ok := fields["path"].(string); ok && path != "" {
		if e, ok := whodata.Default().Lookup(path); ok {
			if e.User != "" {
				fields["user"] = e.User
			}
			if e.ProcessName != "" {
				fields["process_name"] = e.ProcessName
			}
			if e.UID != "" {
				fields["audit_uid"] = e.UID
			}
			if e.PID != "" {
				fields["audit_pid"] = e.PID
			}
			fields["whodata_source"] = e.Source
		}
	}
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// writeWhodataPathsFile drops the list of recursive FIM paths into a
// well-known location that the audit collector reads to install
// `auditctl -w <path>` rules. Decouples the two collectors so the audit
// collector doesn't need to import agent.FileIntegrityCollectorConfig.
// Best-effort: failure is logged silently (we don't have a logger here)
// and just means auto-rule-install is skipped — operators can still
// manage audit rules manually.
func (c *Collector) writeWhodataPathsFile() {
	const helperPath = "/var/lib/watchnode/whodata-paths"
	_ = os.MkdirAll(filepath.Dir(helperPath), 0o755)
	var b []byte
	for _, p := range c.cfg.Paths {
		if p.Path == "" {
			continue
		}
		b = append(b, []byte(p.Path)...)
		b = append(b, '\n')
	}
	_ = os.WriteFile(helperPath, b, 0o644)
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
