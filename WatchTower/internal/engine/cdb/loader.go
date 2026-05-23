package cdb

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Manager owns the set of CDB lists used for threat-intel and other key-value
// lookups during rule matching. All exported methods are safe to call
// concurrently from collector ingestion goroutines (writers) and the rules
// engine hot path (readers).
type Manager struct {
	logger *zap.Logger
	mu     sync.RWMutex
	lists  map[string]*List

	// missMu + missed tracks list names that were looked up but don't exist.
	// We log each missing list name exactly once so a typo in rule YAML is
	// surfaced loudly instead of silently returning false on every event.
	missMu sync.Mutex
	missed map[string]struct{}
}

func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		logger: logger,
		lists:  make(map[string]*List),
		missed: make(map[string]struct{}),
	}
}

func (m *Manager) LoadFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
		list, err := loadListFile(name, path)
		if err != nil {
			m.logger.Warn("failed to load CDB list", zap.String("path", path), zap.Error(err))
			return nil
		}
		m.mu.Lock()
		m.lists[name] = list
		m.mu.Unlock()
		m.logger.Debug("CDB list loaded", zap.String("name", name), zap.Int("entries", list.Count()))
		return nil
	})
}

func loadListFile(name, path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	list := NewList(name)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := ""
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
		list.Add(key, value)
	}
	return list, scanner.Err()
}

// Lookup returns true if the (normalized) key matches an entry in the named
// list. Returns true also for IP keys that fall within a CIDR entry. Logs the
// list name exactly once if the named list does not exist, so rule typos are
// not silent.
func (m *Manager) Lookup(listName, key string) bool {
	m.mu.RLock()
	list, ok := m.lists[listName]
	m.mu.RUnlock()
	if !ok {
		m.logMissingOnce(listName)
		return false
	}
	return list.MatchNormalized(key)
}

func (m *Manager) logMissingOnce(listName string) {
	m.missMu.Lock()
	defer m.missMu.Unlock()
	if _, seen := m.missed[listName]; seen {
		return
	}
	m.missed[listName] = struct{}{}
	if m.logger != nil {
		m.logger.Warn("CDB lookup against unknown list — likely rule misconfiguration",
			zap.String("list", listName),
		)
	}
}

func (m *Manager) GetList(name string) *List {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lists[name]
}

// AddList atomically replaces (or installs) a list by name. Used by the
// threatintel manager when a fetch cycle completes.
func (m *Manager) AddList(list *List) {
	m.mu.Lock()
	m.lists[list.Name()] = list
	m.mu.Unlock()
}

func (m *Manager) ListNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.lists))
	for name := range m.lists {
		names = append(names, name)
	}
	return names
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.lists)
}

// AddEntryToList adds key→value to a named in-memory list, creating the list
// if it does not exist. Used by the SOAR playbook executor for add_to_watchlist.
func (m *Manager) AddEntryToList(listName, key, value string) {
	m.mu.Lock()
	list, ok := m.lists[listName]
	if !ok {
		list = NewList(listName)
		m.lists[listName] = list
	}
	m.mu.Unlock()
	list.Add(key, value)
}

// normalizeKey strips whitespace, port suffix, trailing FQDN dot, and
// lowercases. Without this, rule lookups against TI feeds miss the most
// common log-data shapes: "1.2.3.4 " (trailing space from naive splitters),
// "1.2.3.4:443" (sockaddr), "Example.COM." (DNS canonical form).
func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimSuffix(key, ".")
	key = strings.ToLower(key)
	// Strip trailing :port, but only for v4 or bracketed v6 forms — we don't
	// want to mangle a domain that happens to contain a colon.
	if ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(key, "["), "]")); ip != nil {
		return ip.String()
	}
	// IPv4 with port.
	if idx := strings.LastIndexByte(key, ':'); idx > 0 && strings.Count(key, ":") == 1 {
		if ip := net.ParseIP(key[:idx]); ip != nil {
			return ip.String()
		}
	}
	// Bracketed IPv6 with port: [::1]:443
	if strings.HasPrefix(key, "[") {
		if end := strings.Index(key, "]"); end > 0 {
			if ip := net.ParseIP(key[1:end]); ip != nil {
				return ip.String()
			}
		}
	}
	return key
}
