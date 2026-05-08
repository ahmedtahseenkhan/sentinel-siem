// Package correlation implements time-windowed frequency correlation for the
// WatchTower detection engine.
//
// How it works
// ============
//  1. When a rule has a Threshold block, the engine calls ShouldFire instead
//     of firing immediately.
//  2. ShouldFire bumps a sliding-window counter keyed by
//     (rule_id|agent_id|group_by_value) and returns true only when the count
//     meets or first exceeds the configured threshold within the window.
//  3. After the threshold is first reached the counter resets so subsequent
//     occurrences generate new alerts at the same rate (re-fires every N hits).
//  4. A background GC goroutine prunes stale entries to bound memory.
package correlation

import (
	"fmt"
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

const (
	defaultMaxKeys = 200_000
	gcInterval     = 3 * time.Minute
)

// window holds the ordered list of event timestamps for a single correlation key.
type window struct {
	times []time.Time
}

// Manager maintains sliding-window counters for threshold rules.
type Manager struct {
	mu      sync.Mutex
	windows map[string]*window
	maxKeys int
	logger  *zap.Logger
	stopCh  chan struct{}
}

// New creates a Manager and starts its background GC loop.
func New(logger *zap.Logger) *Manager {
	m := &Manager{
		windows: make(map[string]*window),
		maxKeys: defaultMaxKeys,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
	go m.gcLoop()
	return m
}

// ShouldFire returns true when the event crosses the rule's frequency threshold
// within the configured time period.
//
// For rules without a Threshold block this always returns true (pass-through).
func (m *Manager) ShouldFire(rule *models.Rule, event *models.Event) bool {
	if rule.Threshold == nil {
		return true
	}
	t := rule.Threshold
	if t.Count <= 0 || t.PeriodSecs <= 0 {
		return true
	}

	period := time.Duration(t.PeriodSecs) * time.Second
	groupVal := groupByValue(event, t.GroupBy)
	key := fmt.Sprintf("%d|%s|%s", rule.ID, event.AgentID, groupVal)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-period)

	w, ok := m.windows[key]
	if !ok {
		if len(m.windows) >= m.maxKeys {
			m.evictOldestLocked(period)
		}
		w = &window{}
		m.windows[key] = w
	}

	// Append this event and prune timestamps outside the window.
	w.times = append(w.times, now)
	w.times = pruneOld(w.times, cutoff)

	count := len(w.times)
	if count >= t.Count {
		// Reset counter so the next t.Count hits fire again.
		w.times = nil
		m.logger.Debug("correlation threshold reached",
			zap.Int("rule_id", rule.ID),
			zap.String("agent_id", event.AgentID),
			zap.String("group_by_val", groupVal),
			zap.Int("count", count),
			zap.Duration("period", period),
		)
		return true
	}
	return false
}

// Stop shuts down the background GC goroutine.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// Count returns the current hit count for a (ruleID, agentID, groupVal) key
// within its active window.  Used for testing and diagnostics.
func (m *Manager) Count(ruleID int, agentID, groupVal string, period time.Duration) int {
	key := fmt.Sprintf("%d|%s|%s", ruleID, agentID, groupVal)
	cutoff := time.Now().Add(-period)
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.windows[key]
	if !ok {
		return 0
	}
	w.times = pruneOld(w.times, cutoff)
	return len(w.times)
}

// ─── helpers ────────────────────────────────────────────────────────────────

// groupByValue returns the string value of the configured field from the
// event, or an empty string when the field is not configured or not present.
func groupByValue(event *models.Event, field string) string {
	if field == "" {
		return ""
	}
	if v, ok := event.Fields[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	// Also check decoded fields produced by the decoder pipeline.
	if v, ok := event.Decoded[field]; ok {
		return v
	}
	return ""
}

// pruneOld removes timestamps older than cutoff and returns the trimmed slice.
func pruneOld(times []time.Time, cutoff time.Time) []time.Time {
	// Timestamps are appended in order, so find the first one that's within the window.
	for i, t := range times {
		if t.After(cutoff) {
			return times[i:]
		}
	}
	return times[:0]
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
	// We don't know per-entry periods here, so use a generous max window of
	// 24 hours as the cutoff for GC — anything older is certainly stale.
	cutoff := time.Now().Add(-24 * time.Hour)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, w := range m.windows {
		w.times = pruneOld(w.times, cutoff)
		if len(w.times) == 0 {
			delete(m.windows, key)
		}
	}
}

// evictOldestLocked removes the single entry whose most-recent timestamp is
// oldest.  Must be called with m.mu held.
func (m *Manager) evictOldestLocked(period time.Duration) {
	cutoff := time.Now().Add(-period)
	var oldestKey string
	var oldestTime time.Time
	for k, w := range m.windows {
		w.times = pruneOld(w.times, cutoff)
		if len(w.times) == 0 {
			delete(m.windows, k)
			return
		}
		if oldestKey == "" || w.times[len(w.times)-1].Before(oldestTime) {
			oldestKey = k
			oldestTime = w.times[len(w.times)-1]
		}
	}
	if oldestKey != "" {
		delete(m.windows, oldestKey)
	}
}
