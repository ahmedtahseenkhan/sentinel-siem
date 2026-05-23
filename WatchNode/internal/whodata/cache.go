// Package whodata maintains a small in-memory cache that lets the FIM
// collector answer the question "who changed this file?" by joining its
// own filesystem-notification events with audit events produced by:
//
//   - Linux: auditd (path entries from /var/log/audit/audit.log)
//   - Windows: Security event log entries with EventID 4663 (Object Access)
//
// Each Record() call stores an entry keyed by the absolute filesystem path.
// Lookup() returns the most recent entry whose timestamp is within the
// configured TTL window (default 30s). The cache is bounded and self-pruning
// so a busy host does not accumulate unbounded state.
//
// This package is process-local and intentionally has no persistence — if the
// agent restarts mid-burst the worst case is a few un-attributed FIM events,
// which is preferable to writing every audit record to disk.
package whodata

import (
	"sync"
	"time"
)

// Entry describes who/how a path was touched, as observed by an audit source.
type Entry struct {
	Path        string
	User        string // local username (Linux: auid/uid, Windows: SubjectUserName)
	ProcessName string // exe / Image basename
	UID         string // raw uid (Linux only — empty on Windows)
	PID         string
	Source      string // "auditd" or "eventlog"
	Timestamp   time.Time
}

// DefaultTTL is the maximum age a cached audit entry can have before it is
// considered too stale to attribute a FIM event. Tuned to comfortably cover
// fsnotify -> emit latency while still expiring soon enough that unrelated
// later writes don't pick up the wrong user.
const DefaultTTL = 30 * time.Second

// Cache is a TTL-bounded path -> Entry map.
type Cache struct {
	ttl     time.Duration
	maxSize int

	mu      sync.Mutex
	entries map[string]Entry
	// pruneEvery throttles full-map sweeps; we only do them when the map grows
	// past maxSize, otherwise lookups do per-entry expiry checks.
}

// NewCache returns a Cache configured with ttl (zero means DefaultTTL) and a
// soft maxSize cap (zero means 4096).
func NewCache(ttl time.Duration, maxSize int) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &Cache{
		ttl:     ttl,
		maxSize: maxSize,
		entries: make(map[string]Entry),
	}
}

// Record stores e under e.Path. If the map exceeds maxSize, the oldest
// entries are dropped (best-effort linear sweep — happens rarely).
func (c *Cache) Record(e Entry) {
	if e.Path == "" {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[e.Path] = e
	if len(c.entries) > c.maxSize {
		c.pruneLocked()
	}
}

// Lookup returns the cached entry for path if it exists and has not aged out.
// The TTL check uses time.Now(); callers don't pass their own clock.
func (c *Cache) Lookup(path string) (Entry, bool) {
	if path == "" {
		return Entry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[path]
	if !ok {
		return Entry{}, false
	}
	if time.Since(e.Timestamp) > c.ttl {
		delete(c.entries, path)
		return Entry{}, false
	}
	return e, true
}

// pruneLocked drops everything older than ttl. Called under mu.
func (c *Cache) pruneLocked() {
	cutoff := time.Now().Add(-c.ttl)
	for k, v := range c.entries {
		if v.Timestamp.Before(cutoff) {
			delete(c.entries, k)
		}
	}
}

// Size returns the current cache size — for diagnostics only.
func (c *Cache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ── Package-level shared cache ───────────────────────────────────────────────
// Collectors find each other via this default cache, avoiding the need to
// thread a Cache through every constructor. Tests can swap it via SetDefault.

var defaultCache = NewCache(0, 0)
var defaultMu sync.RWMutex

// Default returns the singleton cache used by the FIM, audit, and eventlog
// collectors.
func Default() *Cache {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultCache
}

// SetDefault replaces the singleton — for tests.
func SetDefault(c *Cache) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultCache = c
}
