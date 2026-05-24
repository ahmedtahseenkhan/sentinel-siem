package enrich

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

func TestPickHashPrefersSHA256(t *testing.T) {
	e := &models.Event{Fields: map[string]interface{}{
		"sha256": "3395856ce81f2b7382dee72602f798b642f14140d0ff9b7d59f3a4d39c44a02e",
		"md5":    "ignored",
	}}
	got, ok := pickHash(e)
	if !ok || len(got) != 64 {
		t.Fatalf("pickHash failed: ok=%v len=%d", ok, len(got))
	}
}

func TestPickIPSkipsPrivate(t *testing.T) {
	cases := []struct {
		ip   string
		want bool // true if it should be picked (not private)
	}{
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"fe80::1", false},
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		e := &models.Event{Fields: map[string]interface{}{"dst_ip": c.ip}}
		_, ok := pickIP(e)
		if ok != c.want {
			t.Errorf("pickIP(%s): got %v want %v", c.ip, ok, c.want)
		}
	}
}

func TestPickDomainNormalises(t *testing.T) {
	e := &models.Event{Fields: map[string]interface{}{
		"QueryName": "EVIL.EXAMPLE.COM.",
	}}
	got, ok := pickDomain(e)
	if !ok || got != "evil.example.com" {
		t.Errorf("pickDomain: got %q ok=%v", got, ok)
	}
}

func TestRateLimiterBucket(t *testing.T) {
	v := NewVirusTotal(VTConfig{Enabled: true, APIKey: "k"}, zap.NewNop())
	// Start with 4 tokens; first 4 should succeed.
	for i := 0; i < 4; i++ {
		if !v.takeToken() {
			t.Fatalf("token %d unexpectedly refused", i)
		}
	}
	// 5th must fail immediately.
	if v.takeToken() {
		t.Error("5th token should have been refused")
	}
}

func TestSkipBelowMinLevel(t *testing.T) {
	// Server that fails the test if hit (it must NOT be called below min_level).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("VT API hit despite alert being below min_level")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	v := NewVirusTotal(VTConfig{Enabled: true, APIKey: "k", MinLevel: 10}, zap.NewNop())
	a := &models.Alert{Level: 5}
	e := &models.Event{Fields: map[string]interface{}{"sha256": "abcd" + string(make([]byte, 60))}}
	v.OnAlert(a, e)
	if a.Enrichment != nil {
		t.Error("Enrichment populated despite below-min-level alert")
	}
}

func TestCacheHitAvoidsAPI(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"id":"x","attributes":{"last_analysis_stats":{"malicious":5}}}}`))
	}))
	defer srv.Close()
	v := NewVirusTotal(VTConfig{Enabled: true, APIKey: "k", MinLevel: 1, CacheTTLSecs: 60}, zap.NewNop())
	// Hand-poison: pre-seed cache via the same code path.
	v.cachePut("ip_addresses:8.8.8.8", map[string]interface{}{"found": true, "malicious": 5})
	a1 := &models.Alert{Level: 10}
	a2 := &models.Alert{Level: 10}
	e := &models.Event{Fields: map[string]interface{}{"dst_ip": "8.8.8.8"}}
	v.OnAlert(a1, e)
	v.OnAlert(a2, e)
	if hits != 0 {
		t.Errorf("expected 0 API hits via cache, got %d", hits)
	}
	if a1.Enrichment == nil || a2.Enrichment == nil {
		t.Error("enrichment missing despite cache hit")
	}
}

func TestVTPermalinkShape(t *testing.T) {
	cases := map[string]string{
		"files":        "https://www.virustotal.com/gui/file/abc",
		"ip_addresses": "https://www.virustotal.com/gui/ip-address/abc",
		"domains":      "https://www.virustotal.com/gui/domain/abc",
	}
	for kind, want := range cases {
		if got := vtPermalink(kind, "abc"); got != want {
			t.Errorf("permalink(%s): got %s want %s", kind, got, want)
		}
	}
}

var _ = time.Now // keep time imported for future timed tests
