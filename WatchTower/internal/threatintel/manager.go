// Package threatintel provides a scheduled threat intelligence feed ingestion
// pipeline that pulls IOCs from public sources and pushes them into WatchTower
// CDB lists so that existing detection rules can match malicious indicators.
//
// Supported sources (configured via config.SourceConfig.Type):
//   - "abuseipdb"     — top abusive IPs (free API with key)
//   - "otx"           — OTX AlienVault IP and domain indicators
//   - "plaintext"     — custom HTTP text feed, one IOC per line
//   - "feodotracker"  — abuse.ch botnet C2 IP blocklist (free, no key)
//   - "abusech_hash"  — abuse.ch MalwareBazaar SHA256 hashes (free, no key)
//   - "urlhaus"       — abuse.ch URLhaus malicious domains (free, no key)
//   - "misp"          — MISP REST search (api_key required; splits output
//                       into <prefix>_ips, _domains, _hashes, _urls)
//
// A configurable interval (default 6h) triggers each enabled source; failures
// are logged but never fatal.
package threatintel

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine/cdb"
	"go.uber.org/zap"
)

// Manager orchestrates scheduled threat intel ingestion.
type Manager struct {
	cfg    config.ThreatIntelConfig
	cdbMgr *cdb.Manager
	logger *zap.Logger
	client *http.Client
}

// New creates a threat intel Manager. It does not start any goroutines.
func New(cfg config.ThreatIntelConfig, cdbMgr *cdb.Manager, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		cdbMgr: cdbMgr,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start begins the periodic ingestion loop. It blocks until ctx is cancelled.
// Call in a goroutine.
func (m *Manager) Start(ctx context.Context) {
	interval, err := time.ParseDuration(m.cfg.Interval)
	if err != nil || interval <= 0 {
		interval = 6 * time.Hour
	}
	m.logger.Info("threat intel manager starting",
		zap.Duration("interval", interval),
		zap.Int("sources", len(m.cfg.Sources)),
	)

	// Run immediately on start, then on interval.
	m.runAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runAll(ctx)
		}
	}
}

// RunOnce triggers a single ingestion pass for all enabled sources.
func (m *Manager) RunOnce(ctx context.Context) {
	m.runAll(ctx)
}

func (m *Manager) runAll(ctx context.Context) {
	for _, src := range m.cfg.Sources {
		if !src.Enabled {
			continue
		}
		if err := m.ingest(ctx, src); err != nil {
			m.logger.Warn("threat intel ingest failed",
				zap.String("source", src.Type),
				zap.String("list", src.ListName),
				zap.Error(err),
			)
		}
	}
}

func (m *Manager) ingest(ctx context.Context, src config.SourceConfig) error {
	var entries map[string]string
	var err error

	switch src.Type {
	case "abuseipdb":
		entries, err = m.fetchAbuseIPDB(ctx, src)
	case "otx":
		entries, err = m.fetchOTX(ctx, src)
	case "plaintext":
		entries, err = m.fetchPlaintext(ctx, src)
	case "feodotracker":
		entries, err = m.fetchFeodoTracker(ctx, src)
	case "abusech_hash":
		entries, err = m.fetchAbusechHash(ctx, src)
	case "urlhaus":
		entries, err = m.fetchURLhaus(ctx, src)
	case "misp":
		// MISP produces multiple typed lists (ips / domains / hashes / urls)
		// directly via cdbMgr; it does not return a single entries map and
		// therefore short-circuits the generic single-list install below.
		return m.ingestMISP(ctx, src)
	default:
		return fmt.Errorf("unknown source type: %s", src.Type)
	}
	if err != nil {
		return err
	}

	listName := src.ListName
	if listName == "" {
		listName = "threatintel-" + string(src.Type)
	}

	// Atomically replace the list: create a fresh List and swap it in.
	newList := cdb.NewList(listName)
	for k, v := range entries {
		newList.Add(k, v)
	}
	m.cdbMgr.AddList(newList)

	m.logger.Info("threat intel list updated",
		zap.String("list", listName),
		zap.Int("entries", len(entries)),
	)
	return nil
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────
// API: https://docs.abuseipdb.com/#blacklist-endpoint
// GET https://api.abuseipdb.com/api/v2/blacklist?limit=10000&plaintext=1
// Returns newline-separated plain IPs with Accept: text/plain, or CSV with
// Accept: application/json (which returns JSON wrapping a list of entries).

func (m *Manager) fetchAbuseIPDB(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	url := src.URL
	if url == "" {
		url = "https://api.abuseipdb.com/api/v2/blacklist?limit=10000"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", src.APIKey)
	req.Header.Set("Accept", "text/plain")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned %d", resp.StatusCode)
	}

	value := src.Value
	if value == "" {
		value = "malicious"
	}

	entries := map[string]string{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) != nil {
			entries[line] = value
		}
	}
	return entries, scanner.Err()
}

// ── OTX AlienVault ────────────────────────────────────────────────────────────
// API: https://otx.alienvault.com/api/v1/indicators/export
// We request the IPv4 type and parse the CSV response.

func (m *Manager) fetchOTX(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	url := src.URL
	if url == "" {
		url = "https://otx.alienvault.com/api/v1/indicators/export?type=IPv4&limit=10000"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if src.APIKey != "" {
		req.Header.Set("X-OTX-API-KEY", src.APIKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otx request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx returned %d", resp.StatusCode)
	}

	value := src.Value
	if value == "" {
		value = "malicious"
	}

	entries := map[string]string{}

	// Try JSON first (OTX wraps results in {"results": [{"indicator": "..."}]})
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, err
	}

	var jsonResp struct {
		Results []struct {
			Indicator string `json:"indicator"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &jsonResp); err == nil && len(jsonResp.Results) > 0 {
		for _, r := range jsonResp.Results {
			if r.Indicator != "" {
				entries[r.Indicator] = value
			}
		}
		return entries, nil
	}

	// Fall back to CSV
	r := csv.NewReader(strings.NewReader(string(body)))
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("otx csv parse: %w", err)
	}
	for _, row := range records {
		if len(row) == 0 {
			continue
		}
		indicator := strings.TrimSpace(row[0])
		if indicator != "" {
			entries[indicator] = value
		}
	}
	return entries, nil
}

// ── Plaintext ─────────────────────────────────────────────────────────────────
// Simple text feed: one indicator per line. Lines starting with # are comments.
// Optionally: "indicator:value" to store a custom value.

func (m *Manager) fetchPlaintext(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	if src.URL == "" {
		return nil, fmt.Errorf("plaintext source requires url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	if src.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+src.APIKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("plaintext request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned %d", resp.StatusCode)
	}

	defaultValue := src.Value
	if defaultValue == "" {
		defaultValue = "malicious"
	}

	entries := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 32*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			if key != "" {
				entries[key] = val
			}
		} else {
			entries[line] = defaultValue
		}
	}
	return entries, scanner.Err()
}

// ── Feodo Tracker ─────────────────────────────────────────────────────────────
// abuse.ch botnet C2 IP blocklist — free, no API key required.
// https://feodotracker.abuse.ch/downloads/ipblocklist.txt

func (m *Manager) fetchFeodoTracker(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	url := src.URL
	if url == "" {
		url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feodotracker request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feodotracker returned %d", resp.StatusCode)
	}

	value := src.Value
	if value == "" {
		value = "c2"
	}

	entries := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) != nil {
			entries[line] = value
		}
	}
	return entries, scanner.Err()
}

// ── abuse.ch MalwareBazaar SHA256 hashes ──────────────────────────────────────
// Recent SHA256 hashes of malware samples — free, no API key required.
// https://bazaar.abuse.ch/export/txt/sha256/recent/

func (m *Manager) fetchAbusechHash(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	url := src.URL
	if url == "" {
		url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abusech_hash request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abusech_hash returned %d", resp.StatusCode)
	}

	value := src.Value
	if value == "" {
		value = "malware"
	}

	entries := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 32*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// SHA256 hashes are exactly 64 hex characters
		if len(line) == 64 {
			entries[strings.ToLower(line)] = value
		}
	}
	return entries, scanner.Err()
}

// ── URLhaus malicious domains ─────────────────────────────────────────────────
// abuse.ch URLhaus — malicious URLs; we extract unique hostnames.
// https://urlhaus.abuse.ch/downloads/text/

func (m *Manager) fetchURLhaus(ctx context.Context, src config.SourceConfig) (map[string]string, error) {
	url := src.URL
	if url == "" {
		url = "https://urlhaus.abuse.ch/downloads/text/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus returned %d", resp.StatusCode)
	}

	value := src.Value
	if value == "" {
		value = "malicious"
	}

	entries := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 32*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract hostname from URL (http://hostname/path or https://hostname/path)
		host := extractHostname(line)
		if host != "" {
			entries[host] = value
		}
	}
	return entries, scanner.Err()
}

func extractHostname(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		return ""
	}
	parts := strings.SplitN(rawURL, "://", 2)
	if len(parts) < 2 {
		return ""
	}
	host := parts[1]
	if idx := strings.IndexByte(host, '/'); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.IndexByte(host, ':'); idx != -1 {
		host = host[:idx]
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, " \t") {
		return ""
	}
	return strings.ToLower(host)
}
