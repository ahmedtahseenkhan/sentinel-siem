package whodata

import (
	"sync"
	"testing"
	"time"
)

func TestRecordLookup(t *testing.T) {
	c := NewCache(5*time.Second, 100)
	c.Record(Entry{Path: "/etc/passwd", User: "root", Source: "auditd"})
	e, ok := c.Lookup("/etc/passwd")
	if !ok {
		t.Fatal("entry not found")
	}
	if e.User != "root" {
		t.Errorf("user = %q, want root", e.User)
	}
}

func TestTTLExpiry(t *testing.T) {
	c := NewCache(20*time.Millisecond, 100)
	c.Record(Entry{Path: "/x", User: "u", Timestamp: time.Now().Add(-30 * time.Millisecond)})
	if _, ok := c.Lookup("/x"); ok {
		t.Error("expected lookup miss after TTL")
	}
}

func TestLookupEmptyPath(t *testing.T) {
	c := NewCache(0, 0)
	if _, ok := c.Lookup(""); ok {
		t.Error("empty path should miss")
	}
}

func TestConcurrentRecordLookup(t *testing.T) {
	c := NewCache(time.Second, 100)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.Record(Entry{Path: "/p", User: "u"})
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = c.Lookup("/p")
			}
		}()
	}
	wg.Wait()
}

func TestDefaultIsShared(t *testing.T) {
	orig := Default()
	defer SetDefault(orig)
	c := NewCache(time.Second, 10)
	SetDefault(c)
	Default().Record(Entry{Path: "/y", User: "alice"})
	e, ok := Default().Lookup("/y")
	if !ok || e.User != "alice" {
		t.Errorf("default cache not shared: %v %v", e, ok)
	}
}
