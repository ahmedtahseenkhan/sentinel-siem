package ueba

import (
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/models"
)

const windowDays = 7

// EventCollector implements engine.UebaHook.
// It maintains thread-safe in-memory sliding windows of behavioral signals
// per agent and per user, which the Analyzer reads each hour.
type EventCollector struct {
	mu       sync.RWMutex
	logins   map[string]*loginWindow   // agentID → login behavior
	networks map[string]*networkWindow // agentID → network behavior
	procs    map[string]*processWindow // agentID → process behavior
	users    map[string]*userWindow    // username → user behavior
}

// NewEventCollector creates an empty collector.
func NewEventCollector() *EventCollector {
	return &EventCollector{
		logins:   make(map[string]*loginWindow),
		networks: make(map[string]*networkWindow),
		procs:    make(map[string]*processWindow),
		users:    make(map[string]*userWindow),
	}
}

// OnEvent is called by the engine for every raw event before rule matching.
func (c *EventCollector) OnEvent(event *models.Event) {
	if event.AgentID == "" {
		return
	}
	switch event.Type {
	case "log.eventlog":
		c.trackLoginEvent(event)
	case "network.connection":
		c.trackNetworkEvent(event)
	case "process.new":
		c.trackProcessEvent(event)
	}
}

// ── Login tracking ────────────────────────────────────────────────────────────

type loginEntry struct {
	ts       time.Time
	hour     int
	sourceIP string
	username string
	failed   bool
}

type loginWindow struct {
	mu      sync.Mutex
	entries []loginEntry
}

func (c *EventCollector) loginWindow(agentID string) *loginWindow {
	if w, ok := c.logins[agentID]; ok {
		return w
	}
	w := &loginWindow{}
	c.logins[agentID] = w
	return w
}

func (c *EventCollector) trackLoginEvent(event *models.Event) {
	winEventID, _ := event.Fields["win_event_id"].(int)
	if winEventID == 0 {
		if v, ok := event.Fields["win_event_id"].(float64); ok {
			winEventID = int(v)
		}
	}
	if winEventID != 4624 && winEventID != 4625 {
		return
	}

	ts := msToTime(event.Timestamp)
	entry := loginEntry{
		ts:       ts,
		hour:     ts.Hour(),
		failed:   winEventID == 4625,
		sourceIP: strField(event, "win_IpAddress"),
		username: strField(event, "win_TargetUserName"),
	}
	if entry.sourceIP == "" {
		entry.sourceIP = strField(event, "win_WorkstationName")
	}

	c.mu.Lock()
	w := c.loginWindow(event.AgentID)
	c.mu.Unlock()

	w.mu.Lock()
	w.entries = append(w.entries, entry)
	w.prune()
	w.mu.Unlock()

	if entry.username != "" {
		c.mu.Lock()
		uw := c.userWindowFor(entry.username)
		c.mu.Unlock()
		uw.mu.Lock()
		uw.record(event.AgentID, entry)
		uw.mu.Unlock()
	}
}

func (w *loginWindow) prune() {
	cutoff := time.Now().AddDate(0, 0, -windowDays)
	i := 0
	for i < len(w.entries) && w.entries[i].ts.Before(cutoff) {
		i++
	}
	w.entries = w.entries[i:]
}

// ── Network tracking ──────────────────────────────────────────────────────────

type networkEntry struct {
	ts   time.Time
	rip  string
	port int
}

type networkWindow struct {
	mu      sync.Mutex
	entries []networkEntry
	seen    map[string]bool // raddr ever seen
}

func (c *EventCollector) networkWindow(agentID string) *networkWindow {
	if w, ok := c.networks[agentID]; ok {
		return w
	}
	w := &networkWindow{seen: make(map[string]bool)}
	c.networks[agentID] = w
	return w
}

func (c *EventCollector) trackNetworkEvent(event *models.Event) {
	status := strField(event, "status")
	if status != "ESTABLISHED" {
		return
	}
	raddr := strField(event, "raddr")
	if raddr == "" || raddr == "0.0.0.0" || raddr == "::" {
		return
	}
	rport := 0
	if v, ok := event.Fields["rport"].(float64); ok {
		rport = int(v)
	}

	c.mu.Lock()
	w := c.networkWindow(event.AgentID)
	c.mu.Unlock()

	w.mu.Lock()
	isNew := !w.seen[raddr]
	w.seen[raddr] = true
	w.entries = append(w.entries, networkEntry{ts: msToTime(event.Timestamp), rip: raddr, port: rport})
	w.prune()
	w.mu.Unlock()

	_ = isNew // used by analyzer via Snapshot
}

func (w *networkWindow) prune() {
	cutoff := time.Now().AddDate(0, 0, -windowDays)
	i := 0
	for i < len(w.entries) && w.entries[i].ts.Before(cutoff) {
		i++
	}
	w.entries = w.entries[i:]
}

// ── Process tracking ──────────────────────────────────────────────────────────

type processEntry struct {
	ts   time.Time
	name string
	hash string
}

type processWindow struct {
	mu        sync.Mutex
	entries   []processEntry
	seenHash  map[string]bool // sha256 ever seen
	seenNames map[string]int  // name → count of days seen
}

func (c *EventCollector) processWindow(agentID string) *processWindow {
	if w, ok := c.procs[agentID]; ok {
		return w
	}
	w := &processWindow{
		seenHash:  make(map[string]bool),
		seenNames: make(map[string]int),
	}
	c.procs[agentID] = w
	return w
}

func (c *EventCollector) trackProcessEvent(event *models.Event) {
	name := strField(event, "name")
	hash := strField(event, "sha256")

	c.mu.Lock()
	w := c.processWindow(event.AgentID)
	c.mu.Unlock()

	w.mu.Lock()
	if hash != "" {
		w.seenHash[hash] = true
	}
	if name != "" {
		w.seenNames[name]++
	}
	w.entries = append(w.entries, processEntry{ts: msToTime(event.Timestamp), name: name, hash: hash})
	w.prune()
	w.mu.Unlock()
}

func (w *processWindow) prune() {
	cutoff := time.Now().AddDate(0, 0, -windowDays)
	i := 0
	for i < len(w.entries) && w.entries[i].ts.Before(cutoff) {
		i++
	}
	w.entries = w.entries[i:]
}

// ── User tracking ─────────────────────────────────────────────────────────────

type userWindow struct {
	mu       sync.Mutex
	agents   map[string]bool // machines this user has logged into
	sourceIPs map[string]bool
	hours    map[int]int // hour → count
	failures int
}

func (c *EventCollector) userWindowFor(username string) *userWindow {
	if w, ok := c.users[username]; ok {
		return w
	}
	w := &userWindow{
		agents:    make(map[string]bool),
		sourceIPs: make(map[string]bool),
		hours:     make(map[int]int),
	}
	c.users[username] = w
	return w
}

func (w *userWindow) record(agentID string, e loginEntry) {
	w.agents[agentID] = true
	if e.sourceIP != "" {
		w.sourceIPs[e.sourceIP] = true
	}
	w.hours[e.hour]++
	if e.failed {
		w.failures++
	}
}

// ── Snapshot types (read by Analyzer) ────────────────────────────────────────

// LoginSnapshot is a point-in-time view of login behavior for one agent.
type LoginSnapshot struct {
	AgentID      string
	Entries      []loginEntry
	FailedCount  int
	UniqueHours  map[int]int
	UniqueIPs    map[string]int
}

// NetworkSnapshot is a point-in-time view of network behavior for one agent.
type NetworkSnapshot struct {
	AgentID        string
	UniqueDestIPs  map[string]int // raddr → count
	TotalConns     int
}

// ProcessSnapshot is a point-in-time view of process behavior for one agent.
type ProcessSnapshot struct {
	AgentID   string
	SeenHashes map[string]bool
	NameCounts map[string]int
	NewEntries []processEntry
}

// UserSnapshot is a point-in-time view of user behavior.
type UserSnapshot struct {
	Username   string
	AgentIDs   []string
	SourceIPs  []string
	Hours      map[int]int
	Failures   int
}

// CollectorSnapshot holds all snapshots at a moment in time.
type CollectorSnapshot struct {
	Logins   []LoginSnapshot
	Networks []NetworkSnapshot
	Procs    []ProcessSnapshot
	Users    []UserSnapshot
	CapturedAt time.Time
}

// Snapshot returns a read-consistent point-in-time copy of all windows.
func (c *EventCollector) Snapshot() CollectorSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := CollectorSnapshot{CapturedAt: time.Now()}

	for agentID, w := range c.logins {
		w.mu.Lock()
		ls := LoginSnapshot{
			AgentID:     agentID,
			Entries:     make([]loginEntry, len(w.entries)),
			UniqueHours: make(map[int]int),
			UniqueIPs:   make(map[string]int),
		}
		copy(ls.Entries, w.entries)
		for _, e := range w.entries {
			ls.UniqueHours[e.hour]++
			if e.sourceIP != "" {
				ls.UniqueIPs[e.sourceIP]++
			}
			if e.failed {
				ls.FailedCount++
			}
		}
		w.mu.Unlock()
		snap.Logins = append(snap.Logins, ls)
	}

	for agentID, w := range c.networks {
		w.mu.Lock()
		ns := NetworkSnapshot{
			AgentID:       agentID,
			UniqueDestIPs: make(map[string]int),
			TotalConns:    len(w.entries),
		}
		for _, e := range w.entries {
			ns.UniqueDestIPs[e.rip]++
		}
		w.mu.Unlock()
		snap.Networks = append(snap.Networks, ns)
	}

	for agentID, w := range c.procs {
		w.mu.Lock()
		ps := ProcessSnapshot{
			AgentID:    agentID,
			SeenHashes: make(map[string]bool, len(w.seenHash)),
			NameCounts: make(map[string]int, len(w.seenNames)),
			NewEntries: make([]processEntry, len(w.entries)),
		}
		for k, v := range w.seenHash {
			ps.SeenHashes[k] = v
		}
		for k, v := range w.seenNames {
			ps.NameCounts[k] = v
		}
		copy(ps.NewEntries, w.entries)
		w.mu.Unlock()
		snap.Procs = append(snap.Procs, ps)
	}

	for username, w := range c.users {
		w.mu.Lock()
		us := UserSnapshot{
			Username: username,
			Hours:    make(map[int]int, len(w.hours)),
			Failures: w.failures,
		}
		for a := range w.agents {
			us.AgentIDs = append(us.AgentIDs, a)
		}
		for ip := range w.sourceIPs {
			us.SourceIPs = append(us.SourceIPs, ip)
		}
		for h, cnt := range w.hours {
			us.Hours[h] = cnt
		}
		w.mu.Unlock()
		snap.Users = append(snap.Users, us)
	}

	return snap
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func strField(event *models.Event, key string) string {
	if v, ok := event.Fields[key].(string); ok {
		return v
	}
	return ""
}

// msToTime converts a Unix millisecond timestamp to time.Time.
func msToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Now()
	}
	return time.UnixMilli(ms)
}
