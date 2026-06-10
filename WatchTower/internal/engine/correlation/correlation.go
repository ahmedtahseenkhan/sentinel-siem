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
	"strings"
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
	count, period, groupFields := effectiveCorrelation(rule)
	if count <= 0 || period <= 0 {
		// Not a frequency rule (or malformed window) — pass through.
		return true
	}

	groupVal := groupByValues(event, groupFields)
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

	hits := len(w.times)
	if hits >= count {
		// Reset counter so the next `count` hits fire again.
		w.times = nil
		m.logger.Debug("correlation threshold reached",
			zap.Int("rule_id", rule.ID),
			zap.String("agent_id", event.AgentID),
			zap.String("group_by_val", groupVal),
			zap.Int("count", hits),
			zap.Duration("period", period),
		)
		return true
	}
	return false
}

// effectiveCorrelation resolves a rule's frequency settings from either the
// `threshold:` block (count/period_secs/group_by string) or the legacy
// `correlation:` block (threshold/window/group_by list). Returns count<=0 when
// the rule is not a (valid) frequency rule, in which case ShouldFire passes
// through. threshold: wins if both are present.
func effectiveCorrelation(rule *models.Rule) (count int, period time.Duration, groupFields []string) {
	if t := rule.Threshold; t != nil && t.Count > 0 && t.PeriodSecs > 0 {
		var gf []string
		if t.GroupBy != "" {
			gf = []string{t.GroupBy}
		}
		return t.Count, time.Duration(t.PeriodSecs) * time.Second, gf
	}
	if c := rule.Correlation; c != nil && c.Threshold > 0 && c.Window != "" {
		if d, err := time.ParseDuration(c.Window); err == nil && d > 0 {
			return c.Threshold, d, c.GroupBy
		}
	}
	return 0, 0, nil
}

// groupByValues concatenates the string values of the configured group-by
// fields (so a rule can correlate on, e.g., [src_ip, dst_ip] as a pair).
func groupByValues(event *models.Event, fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, groupByValue(event, f))
	}
	return strings.Join(parts, "|")
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
