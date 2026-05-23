package cdb

import (
	"sync"
	"testing"

	"go.uber.org/zap"
)

func TestNormalizeIPVariants(t *testing.T) {
	l := NewList("ti_ips")
	l.Add("1.2.3.4", "botnet")

	// All of these must match the same entry. Prior code missed every one.
	for _, in := range []string{
		"1.2.3.4",
		"1.2.3.4 ",    // trailing space (naive log split)
		" 1.2.3.4",    // leading space
		"1.2.3.4:443", // sockaddr
		"[1.2.3.4]",   // bracketed
	} {
		if !l.MatchNormalized(in) {
			t.Errorf("MatchNormalized(%q) = false, want true", in)
		}
	}
}

func TestNormalizeDomainTrailingDot(t *testing.T) {
	l := NewList("ti_domains")
	l.Add("evil.example.com", "c2")

	for _, in := range []string{
		"evil.example.com",
		"evil.example.com.", // DNS canonical form
		"EVIL.EXAMPLE.COM",  // case
	} {
		if !l.MatchNormalized(in) {
			t.Errorf("MatchNormalized(%q) = false, want true", in)
		}
	}
}

func TestCIDREntries(t *testing.T) {
	l := NewList("ti_cidrs")
	l.Add("192.0.2.0/24", "dropnet")
	l.Add("2001:db8::/32", "dropnet6")

	// In-range
	for _, in := range []string{"192.0.2.5", "192.0.2.255", "2001:db8::1"} {
		if !l.MatchNormalized(in) {
			t.Errorf("MatchNormalized(%q) = false, want true (CIDR)", in)
		}
	}
	// Out-of-range
	for _, in := range []string{"192.0.3.1", "10.0.0.1"} {
		if l.MatchNormalized(in) {
			t.Errorf("MatchNormalized(%q) = true, want false", in)
		}
	}
}

func TestManagerUnknownListWarnsOnce(t *testing.T) {
	// Use a no-op observer logger to confirm warning is emitted (not tested
	// content here; the dedupe is what we care about).
	m := NewManager(zap.NewNop())
	_ = m.Lookup("missing_list", "anything")
	_ = m.Lookup("missing_list", "anything")
	m.missMu.Lock()
	_, seen := m.missed["missing_list"]
	m.missMu.Unlock()
	if !seen {
		t.Error("missing list name was not recorded")
	}
}

func TestManagerConcurrentReadWrite(t *testing.T) {
	// Reproduces the data race fixed by the new mutex. Run with -race.
	m := NewManager(zap.NewNop())
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l := NewList("list")
				l.Add("1.2.3.4", "x")
				m.AddList(l)
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = m.Lookup("list", "1.2.3.4")
			}
		}()
	}
	wg.Wait()
}
