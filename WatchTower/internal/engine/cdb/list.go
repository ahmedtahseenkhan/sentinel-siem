package cdb

import "sync"

type List struct {
	name    string
	entries map[string]string
	mu      sync.RWMutex
}

func NewList(name string) *List {
	return &List{
		name:    name,
		entries: make(map[string]string),
	}
}

func (l *List) Add(key, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[key] = value
}

func (l *List) Has(key string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.entries[key]
	return ok
}

func (l *List) Get(key string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	v, ok := l.entries[key]
	return v, ok
}

func (l *List) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
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
