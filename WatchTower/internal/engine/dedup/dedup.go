// Package dedup provides alert deduplication and grouping for the WatchTower
// correlation engine.
//
// Design:
//   - A fingerprint is computed from (rule_id, agent_id, key_field_value).
//   - If an identical fingerprint was last seen within the suppression window
//     the alert is suppressed and an internal counter is incremented.
//   - A background goroutine periodically purges expired entries so the map
//     does not grow unbounded.
package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

const (
	defaultWindow    = 5 * time.Minute
	defaultMaxUnique = 100_000
	gcInterval       = 2 * time.Minute
)

// entry tracks the state for a single dedup fingerprint.
type entry struct {
	firstSeen  time.Time
	lastSeen   time.Time
	count      int64
	suppressed int64
}

// Manager holds the dedup state.
type Manager struct {
	mu      sync.Mutex
	entries map[string]*entry
	window  time.Duration
	maxKeys int
	logger  *zap.Logger
	stopCh  chan struct{}
}

// New creates a Manager with the given suppression window.
// Pass 0 to use the default (5 minutes).
func New(window time.Duration, logger *zap.Logger) *Manager {
	if window <= 0 {
		window = defaultWindow
	}
	m := &Manager{
		entries: make(map[string]*entry),
		window:  window,
		maxKeys: defaultMaxUnique,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
	go m.gcLoop()
	return m
}

// ShouldSuppress returns true when this (rule+agent+key) combination has been
// seen within the current suppression window. It always updates the entry count
// and last-seen time, even when suppressing.
func (m *Manager) ShouldSuppress(alert *models.Alert) bool {
	fp := fingerprint(alert)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	e, ok := m.entries[fp]
	if !ok {
		// First occurrence — allow through and record.
		if len(m.entries) >= m.maxKeys {
			// Evict one entry to cap memory usage.
			m.evictOldestLocked()
		}
		m.entries[fp] = &entry{firstSeen: now, lastSeen: now, count: 1}
		return false
	}

	// Within the suppression window?
	if now.Sub(e.lastSeen) < m.window {
		e.count++
		e.suppressed++
		e.lastSeen = now
		return true
	}

	// Window expired — treat as new occurrence, reset counters.
	e.firstSeen = now
	e.lastSeen = now
	e.count = 1
	e.suppressed = 0
	return false
}

// Stats returns the total number of currently tracked fingerprints.
func (m *Manager) Stats() (tracked int, totalSuppressed int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sup int64
	for _, e := range m.entries {
		sup += e.suppressed
	}
	return len(m.entries), sup
}

// Stop halts the background GC goroutine.
func (m *Manager) Stop() {
	close(m.stopCh)
}

func fingerprint(a *models.Alert) string {
	// Include a representative key field value in the fingerprint so that
	// e.g. two different source IPs producing the same rule still get separate
	// alert counts while repeated identical events are suppressed.
	keyField := extractKeyField(a)
	raw := fmt.Sprintf("%d|%s|%s", a.RuleID, a.AgentID, keyField)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// extractKeyField pulls the most representative discriminating value from the
// alert's event data. Falls back to an empty string when nothing useful exists.
func extractKeyField(a *models.Alert) string {
	// Common discriminating fields in order of preference.
	candidates := []string{"srcip", "dstip", "user", "process_name", "path", "hostname"}
	for _, c := range candidates {
		if v, ok := lookupEventField(a.EventData, c); ok && v != "" {
			return v
		}
	}
	// Fall back to the title so at least same-rule+same-agent is grouped.
	return a.Title
}

// lookupEventField does a lightweight string scan of the JSON event_data for a
// key. This avoids a full json.Unmarshal in a hot path on every alert.
func lookupEventField(eventData, key string) (string, bool) {
	needle := `"` + key + `":"`
	idx := indexOf(eventData, needle)
	if idx < 0 {
		return "", false
	}
	rest := eventData[idx+len(needle):]
	end := indexOf(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (m *Manager) gcLoop() {
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.gc()
		}
	}
}

func (m *Manager) gc() {
	cutoff := time.Now().Add(-m.window)
	m.mu.Lock()
	defer m.mu.Unlock()
	var purged int
	for fp, e := range m.entries {
		if e.lastSeen.Before(cutoff) {
			delete(m.entries, fp)
			purged++
		}
	}
	if purged > 0 {
		m.logger.Debug("dedup gc purged expired entries", zap.Int("purged", purged), zap.Int("remaining", len(m.entries)))
	}
}

func (m *Manager) evictOldestLocked() {
	var oldest string
	var oldestTime time.Time
	for fp, e := range m.entries {
		if oldest == "" || e.lastSeen.Before(oldestTime) {
			oldest = fp
			oldestTime = e.lastSeen
		}
	}
	if oldest != "" {
		delete(m.entries, oldest)
	}
}
