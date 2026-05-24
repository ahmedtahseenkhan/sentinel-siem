package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Microsoft Graph Security API — unified alerts_v2 endpoint.
//
// Reference:
//   https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2
//
// Auth: client_credentials OAuth, resource = https://graph.microsoft.com.
// App registration needs the Application permission `SecurityAlert.Read.All`
// granted by a Global Admin (admin consent required).
//
// The alerts_v2 endpoint unifies these sources into one schema:
//   - Microsoft Defender for Endpoint
//   - Microsoft Defender for Office 365
//   - Microsoft Defender for Cloud Apps
//   - Microsoft Defender for Identity
//   - Microsoft Sentinel
//
// Cursor on lastUpdateDateTime so we pick up status changes (analyst
// triage updates) and not just createdDateTime.

const (
	graphResource     = "https://graph.microsoft.com"
	graphAlertsURL    = "https://graph.microsoft.com/v1.0/security/alerts_v2"
	defenderCursorKey = "defender.alerts"
)

// severityFilters maps the user-friendly MinSeverity to the OData clause.
// Graph severities lowercased: informational, low, medium, high.
// "critical" is not a separate severity in alerts_v2 — high is the top.
var severityFilters = map[string]string{
	"informational": "severity in ('informational','low','medium','high')",
	"low":           "severity in ('low','medium','high')",
	"medium":        "severity in ('medium','high')",
	"high":          "severity in ('high')",
}

func (c *Collector) collectDefender(ctx context.Context) {
	cfg := c.cfg.Defender
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return
	}

	token, err := c.getAzureTokenForResource(ctx, cfg.TenantID, cfg.ClientID, cfg.ClientSecret, graphResource)
	if err != nil {
		c.emit(time.Now(), "cloud.defender.error", map[string]interface{}{
			"provider": "defender", "error": err.Error(),
		}, map[string]string{"provider": "defender"})
		return
	}

	alerts, err := c.fetchDefenderAlerts(ctx, token, cfg.MinSeverity)
	if err != nil {
		c.emit(time.Now(), "cloud.defender.error", map[string]interface{}{
			"provider": "defender", "error": err.Error(),
		}, map[string]string{"provider": "defender"})
		return
	}
	for _, a := range alerts {
		c.emit(time.Now(), "cloud.defender.alert", a, map[string]string{
			"provider": "defender",
			"source":   strOrEmpty(a, "service_source"),
		})
	}
}

func (c *Collector) fetchDefenderAlerts(ctx context.Context, token, minSeverity string) ([]map[string]interface{}, error) {
	since := c.cursorSince(defenderCursorKey)

	sevClause, ok := severityFilters[strings.ToLower(minSeverity)]
	if !ok {
		sevClause = severityFilters["medium"]
	}
	// Combine severity filter with timestamp filter via $filter.
	filter := fmt.Sprintf(
		"%s and lastUpdateDateTime gt %s",
		sevClause,
		since.UTC().Format(time.RFC3339),
	)

	endpoint, _ := url.Parse(graphAlertsURL)
	q := endpoint.Query()
	q.Set("$filter", filter)
	q.Set("$orderby", "lastUpdateDateTime asc")
	q.Set("$top", "200")
	endpoint.RawQuery = q.Encode()

	var all []map[string]interface{}
	var latest time.Time
	nextURL := endpoint.String()
	const maxPages = 5
	for page := 0; page < maxPages && nextURL != ""; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("defender request: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("defender returned %d: %s", resp.StatusCode, snippet(string(body), 300))
		}

		var parsed struct {
			Value    []map[string]interface{} `json:"value"`
			NextLink string                   `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("defender parse: %w", err)
		}

		for _, raw := range parsed.Value {
			flat := flattenDefenderAlert(raw)
			if t, err := time.Parse(time.RFC3339, strOrEmpty(flat, "last_update")); err == nil && t.After(latest) {
				latest = t
			}
			all = append(all, flat)
		}

		nextURL = parsed.NextLink
	}

	if !latest.IsZero() {
		c.cursorAdvance(defenderCursorKey, latest)
	}
	return all, nil
}

// flattenDefenderAlert reduces one alerts_v2 record to the top-level fields
// detection rules and SOC dashboards actually use. Evidence (devices, users,
// files, urls, ips involved in the alert) is summarised into a small set of
// per-type arrays so rules can match like "any evidence.user is in
// privileged_users CDB". Full original record under "raw" for rules needing
// nested fields.
func flattenDefenderAlert(a map[string]interface{}) map[string]interface{} {
	flat := map[string]interface{}{
		"id":               strOrEmpty(a, "id"),
		"provider_alert":   strOrEmpty(a, "providerAlertId"),
		"title":            strOrEmpty(a, "title"),
		"description":      strOrEmpty(a, "description"),
		"category":         strOrEmpty(a, "category"),
		"severity":         strOrEmpty(a, "severity"),
		"status":           strOrEmpty(a, "status"),
		"classification":   strOrEmpty(a, "classification"),
		"determination":    strOrEmpty(a, "determination"),
		"created":          strOrEmpty(a, "createdDateTime"),
		"last_update":      strOrEmpty(a, "lastUpdateDateTime"),
		"first_activity":   strOrEmpty(a, "firstActivityDateTime"),
		"last_activity":    strOrEmpty(a, "lastActivityDateTime"),
		"assigned_to":      strOrEmpty(a, "assignedTo"),
		"service_source":   strOrEmpty(a, "serviceSource"),
		"detection_source": strOrEmpty(a, "detectionSource"),
		"tenant_id":        strOrEmpty(a, "tenantId"),
		"raw":              a,
	}

	// Summarise evidence into per-type slices.
	var users, devices, files, ips, urls []string
	if ev, ok := a["evidence"].([]interface{}); ok {
		for _, item := range ev {
			e, _ := item.(map[string]interface{})
			switch strOrEmpty(e, "@odata.type") {
			case "#microsoft.graph.security.userEvidence":
				if u, _ := e["userAccount"].(map[string]interface{}); u != nil {
					if v := strOrEmpty(u, "userPrincipalName"); v != "" {
						users = append(users, v)
					}
				}
			case "#microsoft.graph.security.deviceEvidence":
				if v := strOrEmpty(e, "deviceDnsName"); v != "" {
					devices = append(devices, v)
				}
			case "#microsoft.graph.security.fileEvidence":
				if f, _ := e["fileDetails"].(map[string]interface{}); f != nil {
					if v := strOrEmpty(f, "fileName"); v != "" {
						files = append(files, v)
					}
				}
			case "#microsoft.graph.security.ipEvidence":
				if v := strOrEmpty(e, "ipAddress"); v != "" {
					ips = append(ips, v)
				}
			case "#microsoft.graph.security.urlEvidence":
				if v := strOrEmpty(e, "url"); v != "" {
					urls = append(urls, v)
				}
			}
		}
	}
	if len(users) > 0 {
		flat["evidence_users"] = users
	}
	if len(devices) > 0 {
		flat["evidence_devices"] = devices
	}
	if len(files) > 0 {
		flat["evidence_files"] = files
	}
	if len(ips) > 0 {
		flat["evidence_ips"] = ips
	}
	if len(urls) > 0 {
		flat["evidence_urls"] = urls
	}
	return flat
}
