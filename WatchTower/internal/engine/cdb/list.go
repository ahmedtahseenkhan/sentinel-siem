package cdb

import (
	"net"
	"strings"
	"sync"
)

// List is a named key→value map used for CDB lookups during rule matching.
// When an entry is added in CIDR form (e.g. "192.0.2.0/24"), it is stored
// separately so IP lookups can fall back to subnet membership — TI feeds
// like Spamhaus DROP and parts of Feodo Tracker publish CIDR ranges that
// the prior implementation silently rejected via net.ParseIP.
type List struct {
	name    string
	mu      sync.RWMutex
	entries map[string]string

	// cidrs is kept as a parallel slice. Small enough for linear scan at the
	// scales TI feeds produce (≤ low thousands); a radix trie is a future
	// optimization if needed.
	cidrs []cidrEntry
}

type cidrEntry struct {
	net   *net.IPNet
	value string
}

func NewList(name string) *List {
	return &List{
		name:    name,
		entries: make(map[string]string),
	}
}

// Add inserts key→value. If key parses as a CIDR it is indexed separately
// for subnet membership lookups; otherwise it's stored as a plain map entry.
// The key is lowercased so a single canonical form is used for both ingest
// and lookup.
func (l *List) Add(key, value string) {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ipnet, err := net.ParseCIDR(key); err == nil {
		l.cidrs = append(l.cidrs, cidrEntry{net: ipnet, value: value})
		return
	}
	l.entries[key] = value
}

func (l *List) Has(key string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.entries[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

// MatchNormalized normalizes key (whitespace, port, FQDN dot, case) and
// returns true if it matches an exact entry OR falls within any CIDR entry.
// This is the lookup path used by the rules engine; the prior Manager.Lookup
// used raw map Has() which silently missed "1.2.3.4 " / "1.2.3.4:443" /
// "Example.COM." and never consulted CIDR ranges at all.
func (l *List) MatchNormalized(key string) bool {
	norm := normalizeKey(key)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if _, ok := l.entries[norm]; ok {
		return true
	}
	if len(l.cidrs) == 0 {
		return false
	}
	ip := net.ParseIP(norm)
	if ip == nil {
		return false
	}
	for _, c := range l.cidrs {
		if c.net.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *List) Get(key string) (string, bool) {
	norm := normalizeKey(key)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if v, ok := l.entries[norm]; ok {
		return v, true
	}
	if ip := net.ParseIP(norm); ip != nil {
		for _, c := range l.cidrs {
			if c.net.Contains(ip) {
				return c.value, true
			}
		}
	}
	return "", false
}

func (l *List) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries) + len(l.cidrs)
}

func (l *List) Name() string {
	return l.name
}

func (l *List) Entries() map[string]string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cp := make(map[string]string, len(l.entries))
	for k, v := range l.entries {
		cp[k] = v
	}
	return cp
}
