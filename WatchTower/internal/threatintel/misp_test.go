package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine/cdb"
	"go.uber.org/zap"
)

func TestMISPSplitsByType(t *testing.T) {
	// Fixture exercises:
	//   - plain ip-src
	//   - ip-dst|port (port stripped)
	//   - domain
	//   - domain|ip (yields BOTH a domain and an ip entry)
	//   - sha256 (lowercased)
	//   - url
	//   - unknown type (ignored, no panic)
	fixture := `{"response":[{"Event":{"id":"1","info":"test","Attribute":[
		{"type":"ip-src","value":"8.8.8.8"},
		{"type":"ip-dst|port","value":"1.2.3.4|443"},
		{"type":"domain","value":"evil.example.com"},
		{"type":"domain|ip","value":"bad.example.org|5.6.7.8"},
		{"type":"sha256","value":"3395856CE81F2B7382DEE72602F798B642F14140D0FF9B7D59F3A4D39C44A02E"},
		{"type":"url","value":"http://malware.example.com/x"},
		{"type":"unknown-type","value":"ignored"}
	]}}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "test-key" {
			t.Errorf("missing/incorrect API key header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fixture))
	}))
	defer srv.Close()

	cdbMgr := cdb.NewManager(zap.NewNop())
	m := New(config.ThreatIntelConfig{}, cdbMgr, zap.NewNop())

	if err := m.ingestMISP(context.Background(), config.SourceConfig{
		Type:   "misp",
		URL:    srv.URL,
		APIKey: "test-key",
	}); err != nil {
		t.Fatalf("ingestMISP: %v", err)
	}

	// Verify each typed list landed with the right entries.
	if !cdbMgr.Lookup("misp_ips", "8.8.8.8") {
		t.Error("misp_ips missing 8.8.8.8")
	}
	if !cdbMgr.Lookup("misp_ips", "1.2.3.4") {
		t.Error("misp_ips missing 1.2.3.4 (ip-dst|port should strip port)")
	}
	if !cdbMgr.Lookup("misp_ips", "5.6.7.8") {
		t.Error("misp_ips missing 5.6.7.8 (domain|ip should emit BOTH)")
	}
	if !cdbMgr.Lookup("misp_domains", "evil.example.com") {
		t.Error("misp_domains missing evil.example.com")
	}
	if !cdbMgr.Lookup("misp_domains", "bad.example.org") {
		t.Error("misp_domains missing bad.example.org (domain|ip)")
	}
	if !cdbMgr.Lookup("misp_hashes", "3395856ce81f2b7382dee72602f798b642f14140d0ff9b7d59f3a4d39c44a02e") {
		t.Error("misp_hashes missing sha256 (should be lowercased)")
	}
	if !cdbMgr.Lookup("misp_urls", "http://malware.example.com/x") {
		t.Error("misp_urls missing url")
	}
}

func TestMISPRequiresURLAndKey(t *testing.T) {
	m := New(config.ThreatIntelConfig{}, cdb.NewManager(zap.NewNop()), zap.NewNop())
	if err := m.ingestMISP(context.Background(), config.SourceConfig{Type: "misp", APIKey: "k"}); err == nil {
		t.Error("expected error when URL missing")
	}
	if err := m.ingestMISP(context.Background(), config.SourceConfig{Type: "misp", URL: "http://x"}); err == nil {
		t.Error("expected error when api_key missing")
	}
}

func TestMISPListNamePrefix(t *testing.T) {
	fixture := `{"response":[{"Event":{"Attribute":[{"type":"ip-src","value":"9.9.9.9"}]}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	}))
	defer srv.Close()
	cdbMgr := cdb.NewManager(zap.NewNop())
	m := New(config.ThreatIntelConfig{}, cdbMgr, zap.NewNop())
	if err := m.ingestMISP(context.Background(), config.SourceConfig{
		Type:     "misp",
		URL:      srv.URL,
		APIKey:   "k",
		ListName: "circl",
	}); err != nil {
		t.Fatalf("ingestMISP: %v", err)
	}
	if !cdbMgr.Lookup("circl_ips", "9.9.9.9") {
		t.Error("list_name prefix not honored — expected circl_ips list")
	}
}
