// Package enrich provides alert enrichment plugins called between the rules
// engine's match step and alert storage. Enrichers attach external context
// (threat-intel reputation, geolocation, etc.) to outgoing alerts so SOC
// analysts get pre-decorated tickets instead of needing to pivot manually.
//
// virustotal.go: VirusTotal v3 reputation lookups for hashes, IPs, and
// domains observed in alert events. Designed for the free public API tier
// (4 req/min, 500 req/day) — uses a token-bucket rate limiter and an
// in-memory TTL cache so repeated alerts on the same IoC don't burn quota.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// VTConfig configures the VirusTotal enricher.
type VTConfig struct {
	Enabled bool `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
	// MinLevel skips enrichment for low-severity alerts to preserve quota.
	// Defaults to 10 if zero, matching the SIEM convention that rule levels
	// >= 10 are SOC-actionable.
	MinLevel int `yaml:"min_level"`
	// CacheTTLSecs controls how long a successful lookup is reused. Default
	// 1 hour. Lower for very dynamic feeds, higher to spare the daily quota.
	CacheTTLSecs int `yaml:"cache_ttl_secs"`
}

// VirusTotal is an alert enricher. Implements the engine's EnricherHook
// interface via OnAlert.
type VirusTotal struct {
	cfg    VTConfig
	client *http.Client
	logger *zap.Logger

	// Token bucket: 4 requests per minute on the free tier.
	bucketMu sync.Mutex
	tokens   int
	lastTick time.Time

	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

type cacheEntry struct {
	payload map[string]interface{}
	expires time.Time
}

// NewVirusTotal returns a configured enricher. Call OnAlert from the engine.
func NewVirusTotal(cfg VTConfig, logger *zap.Logger) *VirusTotal {
	if cfg.MinLevel == 0 {
		cfg.MinLevel = 10
	}
	if cfg.CacheTTLSecs == 0 {
		cfg.CacheTTLSecs = 3600
	}
	return &VirusTotal{
		cfg:      cfg,
		client:   &http.Client{Timeout: 15 * time.Second},
		logger:   logger,
		tokens:   4,
		lastTick: time.Now(),
		cache:    map[string]cacheEntry{},
	}
}

// OnAlert is the EnricherHook entry point. Synchronous so the enriched data
// lands in the same Alert that is stored / forwarded / notified about.
// Returns quickly when disabled, below the level threshold, or when the
// event has no IoC to look up.
func (v *VirusTotal) OnAlert(a *models.Alert, event *models.Event) {
	if !v.cfg.Enabled || v.cfg.APIKey == "" {
		return
	}
	if a.Level < v.cfg.MinLevel {
		return
	}
	if event == nil {
		return
	}

	// Pick the first IoC we recognise in event.Fields. Prefer hash because
	// VT's hash reports are richest; fall back to IP, then domain.
	if h, ok := pickHash(event); ok {
		if pl := v.lookup(context.Background(), "files", h); pl != nil {
			v.attach(a, "virustotal", pl)
			return
		}
	}
	if ip, ok := pickIP(event); ok {
		if pl := v.lookup(context.Background(), "ip_addresses", ip); pl != nil {
			v.attach(a, "virustotal", pl)
			return
		}
	}
	if d, ok := pickDomain(event); ok {
		if pl := v.lookup(context.Background(), "domains", d); pl != nil {
			v.attach(a, "virustotal", pl)
			return
		}
	}
}

func (v *VirusTotal) attach(a *models.Alert, src string, payload map[string]interface{}) {
	if a.Enrichment == nil {
		a.Enrichment = map[string]interface{}{}
	}
	a.Enrichment[src] = payload
}

// lookup hits VT v3 and returns a compact payload with the fields a SOC
// analyst actually wants: malicious/suspicious detection counts, the
// permalink, and a few headline attributes. nil on rate-limit, cache miss
// fallback failure, or any HTTP error — we never block the alert pipeline
// on enrichment.
func (v *VirusTotal) lookup(ctx context.Context, kind, ioc string) map[string]interface{} {
	cacheKey := kind + ":" + ioc
	v.cacheMu.Lock()
	if e, ok := v.cache[cacheKey]; ok && time.Now().Before(e.expires) {
		v.cacheMu.Unlock()
		return e.payload
	}
	v.cacheMu.Unlock()

	if !v.takeToken() {
		v.logger.Debug("vt rate limited", zap.String("ioc", ioc))
		return nil
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/%s/%s", kind, ioc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-apikey", v.cfg.APIKey)

	resp, err := v.client.Do(req)
	if err != nil {
		v.logger.Debug("vt request failed", zap.Error(err))
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode == http.StatusNotFound {
		// Cache the negative answer so we don't re-query an unknown IoC.
		neg := map[string]interface{}{"found": false}
		v.cachePut(cacheKey, neg)
		return neg
	}
	if resp.StatusCode != http.StatusOK {
		v.logger.Debug("vt non-200", zap.Int("status", resp.StatusCode))
		return nil
	}

	var parsed struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				Reputation        int      `json:"reputation"`
				Tags              []string `json:"tags"`
				MeaningfulName    string   `json:"meaningful_name,omitempty"`
				TypeDescription   string   `json:"type_description,omitempty"`
				Country           string   `json:"country,omitempty"`
				ASOwner           string   `json:"as_owner,omitempty"`
				Registrar         string   `json:"registrar,omitempty"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	stats := parsed.Data.Attributes.LastAnalysisStats
	out := map[string]interface{}{
		"found":      true,
		"id":         parsed.Data.ID,
		"malicious":  stats.Malicious,
		"suspicious": stats.Suspicious,
		"harmless":   stats.Harmless,
		"undetected": stats.Undetected,
		"reputation": parsed.Data.Attributes.Reputation,
		"tags":       parsed.Data.Attributes.Tags,
		"permalink":  vtPermalink(kind, ioc),
	}
	if v := parsed.Data.Attributes.MeaningfulName; v != "" {
		out["name"] = v
	}
	if v := parsed.Data.Attributes.TypeDescription; v != "" {
		out["type"] = v
	}
	if v := parsed.Data.Attributes.Country; v != "" {
		out["country"] = v
	}
	if v := parsed.Data.Attributes.ASOwner; v != "" {
		out["as_owner"] = v
	}
	if v := parsed.Data.Attributes.Registrar; v != "" {
		out["registrar"] = v
	}
	v.cachePut(cacheKey, out)
	return out
}

func (v *VirusTotal) cachePut(key string, payload map[string]interface{}) {
	v.cacheMu.Lock()
	v.cache[key] = cacheEntry{
		payload: payload,
		expires: time.Now().Add(time.Duration(v.cfg.CacheTTLSecs) * time.Second),
	}
	// Soft cap: prune oldest if we exceed 5000 entries.
	if len(v.cache) > 5000 {
		cutoff := time.Now()
		for k, e := range v.cache {
			if e.expires.Before(cutoff) {
				delete(v.cache, k)
			}
		}
	}
	v.cacheMu.Unlock()
}

// takeToken returns true if a token was available. Refills at 4 tokens/min
// to match the free-tier rate limit. Production keys (4,000/min) can simply
// configure cache_ttl_secs lower.
func (v *VirusTotal) takeToken() bool {
	v.bucketMu.Lock()
	defer v.bucketMu.Unlock()
	now := time.Now()
	elapsed := now.Sub(v.lastTick)
	if refill := int(elapsed / (15 * time.Second)); refill > 0 {
		v.tokens += refill
		if v.tokens > 4 {
			v.tokens = 4
		}
		v.lastTick = now
	}
	if v.tokens <= 0 {
		return false
	}
	v.tokens--
	return true
}

func vtPermalink(kind, ioc string) string {
	pathSeg := map[string]string{
		"files":        "file",
		"ip_addresses": "ip-address",
		"domains":      "domain",
	}[kind]
	if pathSeg == "" {
		pathSeg = kind
	}
	return "https://www.virustotal.com/gui/" + pathSeg + "/" + ioc
}

// ── IoC extraction from event.Fields ─────────────────────────────────────────
// Pick the first plausible IoC from common field names. Returns the IoC and
// whether one was found. Ordering matters: hash > ip > domain because hash
// reports are most analytically valuable.

func pickHash(e *models.Event) (string, bool) {
	for _, k := range []string{"sha256", "SHA256", "Hashes", "hash"} {
		if v, ok := e.Fields[k].(string); ok && len(v) == 64 && isHex(v) {
			return strings.ToLower(v), true
		}
	}
	return "", false
}

func pickIP(e *models.Event) (string, bool) {
	for _, k := range []string{"DestinationIp", "destination_ip", "dst_ip", "remote_addr", "SourceIp", "source_ip", "src_ip", "IpAddress"} {
		if v, ok := e.Fields[k].(string); ok {
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil && !isPrivateIP(ip) {
				return ip.String(), true
			}
		}
	}
	return "", false
}

func pickDomain(e *models.Event) (string, bool) {
	for _, k := range []string{"QueryName", "query", "hostname", "DestinationHostname", "destination_hostname"} {
		if v, ok := e.Fields[k].(string); ok {
			d := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(v)), ".")
			if d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, " /\\") {
				return d, true
			}
		}
	}
	return "", false
}

func isPrivateIP(ip net.IP) bool {
	// Don't waste VT quota on RFC1918, loopback, link-local.
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"fc00::/7", "fe80::/10", "::1/128",
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
