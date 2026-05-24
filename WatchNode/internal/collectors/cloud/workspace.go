package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Google Workspace Admin SDK Reports API.
//
// Reference:
//   https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
//
// Auth: GCP service-account JWT with domain-wide delegation enabled and
//       sub=admin@workspace-domain. Scope:
//         https://www.googleapis.com/auth/admin.reports.audit.readonly
//
// Endpoint:
//   GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/
//       applications/{applicationName}
//
// applicationName values relevant to SOC use:
//   - admin   (admin console actions: role grants, OU changes, settings)
//   - login   (sign-ins, failed sign-ins, suspicious logins)
//   - drive   (file shares, access, downloads)
//   - token   (OAuth grants — third-party app authorisations)
//
// Cursor: id.time on each activity (RFC3339 with nanos).
// Pagination: nextPageToken on the response.

const wsScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

var defaultWorkspaceApps = []string{"admin", "login", "drive", "token"}

func (c *Collector) collectWorkspace(ctx context.Context) {
	cfg := c.cfg.Workspace
	if cfg.CredentialsFile == "" || cfg.Subject == "" {
		return
	}
	token, err := c.getGCPTokenScoped(ctx, cfg.CredentialsFile, []string{wsScope}, cfg.Subject)
	if err != nil {
		c.emit(time.Now(), "cloud.workspace.error", map[string]interface{}{
			"provider": "workspace", "error": err.Error(),
		}, map[string]string{"provider": "workspace"})
		return
	}

	apps := cfg.Applications
	if len(apps) == 0 {
		apps = defaultWorkspaceApps
	}

	for _, app := range apps {
		events, err := c.fetchWorkspaceActivities(ctx, token, app)
		if err != nil {
			c.emit(time.Now(), "cloud.workspace.error", map[string]interface{}{
				"provider": "workspace", "application": app, "error": err.Error(),
			}, map[string]string{"provider": "workspace", "application": app})
			continue
		}
		for _, ev := range events {
			c.emit(time.Now(), "cloud.workspace.audit", ev, map[string]string{
				"provider":    "workspace",
				"application": app,
			})
		}
	}
}

// fetchWorkspaceActivities pulls activities for one applicationName since
// the cursor, following nextPageToken until exhausted (bounded to keep one
// poll cycle from running away on a flood).
func (c *Collector) fetchWorkspaceActivities(ctx context.Context, token, app string) ([]map[string]interface{}, error) {
	cursorKey := "workspace.audit." + app
	since := c.cursorSince(cursorKey)

	var all []map[string]interface{}
	var latest time.Time
	pageToken := ""
	const maxPages = 10
	for page := 0; page < maxPages; page++ {
		u := url.URL{
			Scheme: "https",
			Host:   "admin.googleapis.com",
			Path:   "/admin/reports/v1/activity/users/all/applications/" + app,
		}
		q := u.Query()
		q.Set("startTime", since.UTC().Format(time.RFC3339))
		q.Set("maxResults", "1000")
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("workspace activities: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("workspace activities returned %d: %s", resp.StatusCode, snippet(string(body), 300))
		}

		var parsed struct {
			Items         []map[string]interface{} `json:"items"`
			NextPageToken string                   `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("workspace parse: %w", err)
		}

		for _, item := range parsed.Items {
			flat := flattenWorkspaceActivity(item)
			if t, err := time.Parse(time.RFC3339Nano, strOrEmpty(flat, "time")); err == nil && t.After(latest) {
				latest = t
			}
			all = append(all, flat)
		}

		if parsed.NextPageToken == "" {
			break
		}
		pageToken = parsed.NextPageToken
	}

	if !latest.IsZero() {
		c.cursorAdvance(cursorKey, latest)
	}
	return all, nil
}

// flattenWorkspaceActivity normalises one activity record into the shape
// referenced by detection rules in batch 4800 (workspace_admin /
// admin.reports). The full nested record is preserved under "raw".
//
// Schema highlights:
//   id.time      RFC3339 nanos timestamp
//   id.uniqueQualifier
//   actor.email  user that performed the action
//   actor.ipAddress
//   events[].name e.g. "login_success", "ASSIGN_ROLE", "change_user_password"
//   events[].parameters[] name+value/multiValue/intValue
func flattenWorkspaceActivity(item map[string]interface{}) map[string]interface{} {
	id, _ := item["id"].(map[string]interface{})
	actor, _ := item["actor"].(map[string]interface{})
	flat := map[string]interface{}{
		"time":             strOrEmpty(id, "time"),
		"unique_qualifier": strOrEmpty(id, "uniqueQualifier"),
		"actor_email":      strOrEmpty(actor, "email"),
		"actor_caller":     strOrEmpty(actor, "callerType"),
		"actor_ip":         strOrEmpty(item, "ipAddress"),
		"raw":              item,
	}
	// First event name + type for easy rule matching; full list under raw.
	if evs, ok := item["events"].([]interface{}); ok && len(evs) > 0 {
		if ev, ok := evs[0].(map[string]interface{}); ok {
			flat["event_name"] = strOrEmpty(ev, "name")
			flat["event_type"] = strOrEmpty(ev, "type")
		}
	}
	return flat
}
