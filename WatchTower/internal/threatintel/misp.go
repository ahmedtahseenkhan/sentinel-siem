package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine/cdb"
	"go.uber.org/zap"
)

// MISP REST search response shape. We pull only what we need for IoC
// extraction: each event has a list of attributes with a `type` and `value`.
// Many other fields (orgc, info, distribution, ...) are ignored.
type mispResponse struct {
	Response []struct {
		Event struct {
			ID         string `json:"id"`
			Info       string `json:"info"`
			Attribute  []mispAttr `json:"Attribute"`
		} `json:"Event"`
	} `json:"response"`
}

type mispAttr struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Category string `json:"category"`
	Comment  string `json:"comment"`
}

// ingestMISP fetches a MISP REST search and routes each attribute into the
// appropriate CDB list by type. Splitting per type lets rules disambiguate
// "is this IP in MISP" from "is this hash in MISP" by keeping each type in
// its own list. List names default to "misp_ips" / "misp_domains" / "misp_hashes"
// when src.ListName is empty; otherwise that string is used as the prefix.
//
// Auth: MISP servers want the API key in the Authorization header
// (not "Bearer", just the raw key) and Accept: application/json.
func (m *Manager) ingestMISP(ctx context.Context, src config.SourceConfig) error {
	if src.URL == "" {
		return fmt.Errorf("misp source requires url (e.g. https://misp.example.org)")
	}
	if src.APIKey == "" {
		return fmt.Errorf("misp source requires api_key")
	}

	// Default search: published events, last 30 days. Keeps response size
	// bounded; operators wanting more can override via URL with explicit
	// /events/restSearch path + query params.
	endpoint := strings.TrimRight(src.URL, "/")
	if !strings.Contains(endpoint, "/restSearch") {
		endpoint += "/events/restSearch"
	}
	body := bytes.NewBufferString(`{"returnFormat":"json","published":true,"last":"30d","limit":1000}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", src.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("misp request: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("misp returned %d: %s", resp.StatusCode, snippet(string(rawBody), 200))
	}

	var parsed mispResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return fmt.Errorf("misp parse: %w", err)
	}

	prefix := src.ListName
	if prefix == "" {
		prefix = "misp"
	}
	value := src.Value
	if value == "" {
		value = "misp"
	}

	ipList := cdb.NewList(prefix + "_ips")
	domList := cdb.NewList(prefix + "_domains")
	hashList := cdb.NewList(prefix + "_hashes")
	urlList := cdb.NewList(prefix + "_urls")

	ipN, domN, hashN, urlN := 0, 0, 0, 0
	for _, e := range parsed.Response {
		for _, a := range e.Event.Attribute {
			v := strings.TrimSpace(a.Value)
			if v == "" {
				continue
			}
			label := value
			if a.Comment != "" {
				label = value + " (" + strings.ReplaceAll(a.Comment, "\n", " ") + ")"
			}
			switch strings.ToLower(a.Type) {
			case "ip-src", "ip-dst", "ip-src|port", "ip-dst|port":
				// Strip optional |port form.
				if idx := strings.IndexByte(v, '|'); idx > 0 {
					v = v[:idx]
				}
				if net.ParseIP(v) != nil {
					ipList.Add(v, label)
					ipN++
				}
			case "domain", "hostname", "domain|ip":
				// domain|ip values look like "evil.example.com|1.2.3.4"
				if idx := strings.IndexByte(v, '|'); idx > 0 {
					domList.Add(v[:idx], label)
					if ip := v[idx+1:]; net.ParseIP(ip) != nil {
						ipList.Add(ip, label)
						ipN++
					}
				} else {
					domList.Add(v, label)
				}
				domN++
			case "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash":
				hashList.Add(strings.ToLower(v), label)
				hashN++
			case "url", "uri":
				urlList.Add(v, label)
				urlN++
			}
		}
	}

	// Atomically install each list (only if non-empty so we don't blow
	// away a prior good list with zero entries on a bad fetch).
	if ipN > 0 {
		m.cdbMgr.AddList(ipList)
	}
	if domN > 0 {
		m.cdbMgr.AddList(domList)
	}
	if hashN > 0 {
		m.cdbMgr.AddList(hashList)
	}
	if urlN > 0 {
		m.cdbMgr.AddList(urlList)
	}

	m.logger.Info("misp feed ingested",
		zap.String("prefix", prefix),
		zap.Int("events", len(parsed.Response)),
		zap.Int("ips", ipN),
		zap.Int("domains", domN),
		zap.Int("hashes", hashN),
		zap.Int("urls", urlN),
	)
	return nil
}

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
