package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Office 365 Management Activity API constants.
//
// API reference:
//   https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
//
// Flow:
//   1. (once per content type) POST .../subscriptions/start?contentType=X
//   2. (every poll)            GET  .../subscriptions/content?contentType=X
//   3. (per blob)              GET  <contentUri> returned by #2
//
// Each content blob is a JSON array of audit records with a stable schema
// (CreationTime, Id, Operation, Workload, UserId, ClientIP, ...).

const (
	o365APIBase  = "https://manage.office.com/api/v1.0"
	o365Resource = "https://manage.office.com"
)

// defaultO365ContentTypes are the four free streams every E1+ tenant has.
// DLP.All requires E5 or DLP add-on and is not enabled by default.
var defaultO365ContentTypes = []string{
	"Audit.AzureActiveDirectory",
	"Audit.Exchange",
	"Audit.SharePoint",
	"Audit.General",
}

// o365SubscribedOnce remembers which (tenant, contentType) pairs we have
// already subscribed during this process lifetime. /start is idempotent
// against the API but wasteful to call every poll.
var (
	o365SubMu        sync.Mutex
	o365SubscribedOK = map[string]struct{}{}
)

func (c *Collector) collectO365(ctx context.Context) {
	cfg := c.cfg.O365
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return
	}
	token, err := c.getAzureTokenForResource(ctx, cfg.TenantID, cfg.ClientID, cfg.ClientSecret, o365Resource)
	if err != nil {
		c.emit(time.Now(), "cloud.o365.error", map[string]interface{}{
			"provider": "o365", "error": err.Error(),
		}, map[string]string{"provider": "o365"})
		return
	}

	contentTypes := cfg.ContentTypes
	if len(contentTypes) == 0 {
		contentTypes = defaultO365ContentTypes
	}

	for _, ct := range contentTypes {
		if err := c.ensureO365Subscription(ctx, cfg.TenantID, token, ct); err != nil {
			c.emit(time.Now(), "cloud.o365.error", map[string]interface{}{
				"provider": "o365", "content_type": ct, "phase": "subscribe", "error": err.Error(),
			}, map[string]string{"provider": "o365", "content_type": ct})
			continue
		}
		events, err := c.fetchO365Content(ctx, cfg.TenantID, token, ct)
		if err != nil {
			c.emit(time.Now(), "cloud.o365.error", map[string]interface{}{
				"provider": "o365", "content_type": ct, "phase": "fetch", "error": err.Error(),
			}, map[string]string{"provider": "o365", "content_type": ct})
			continue
		}
		for _, ev := range events {
			c.emit(time.Now(), "cloud.o365.audit", ev, map[string]string{
				"provider":     "o365",
				"content_type": ct,
			})
		}
	}
}

// ensureO365Subscription starts a subscription if we haven't already done so
// for this (tenant, contentType). The API returns 200 the first time and
// either 200 or "subscription already exists" subsequently; both are fine.
func (c *Collector) ensureO365Subscription(ctx context.Context, tenantID, token, contentType string) error {
	key := tenantID + "|" + contentType
	o365SubMu.Lock()
	if _, done := o365SubscribedOK[key]; done {
		o365SubMu.Unlock()
		return nil
	}
	o365SubMu.Unlock()

	u := fmt.Sprintf("%s/%s/activity/feed/subscriptions/start?contentType=%s",
		o365APIBase, tenantID, url.QueryEscape(contentType))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Length", "0")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("o365 subscribe: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	switch {
	case resp.StatusCode == http.StatusOK:
		// fresh subscription
	case resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "alreadyExists"):
		// idempotent — treat as success
	default:
		return fmt.Errorf("o365 subscribe returned %d: %s", resp.StatusCode, snippet(string(body), 300))
	}
	o365SubMu.Lock()
	o365SubscribedOK[key] = struct{}{}
	o365SubMu.Unlock()
	return nil
}

// fetchO365Content lists available content blobs newer than the cursor and
// downloads each. Cursor is the contentCreated of the newest blob seen.
// Content blobs are immutable so we don't need a seen-set; the cursor alone
// is sufficient to dedupe across polls.
func (c *Collector) fetchO365Content(ctx context.Context, tenantID, token, contentType string) ([]map[string]interface{}, error) {
	cursorKey := "o365.audit." + contentType
	since := c.cursorSince(cursorKey)

	listURL := fmt.Sprintf("%s/%s/activity/feed/subscriptions/content?contentType=%s&startTime=%s&endTime=%s",
		o365APIBase, tenantID, url.QueryEscape(contentType),
		url.QueryEscape(since.UTC().Format("2006-01-02T15:04:05")),
		url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05")),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("o365 list content: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("o365 list content returned %d: %s", resp.StatusCode, snippet(string(body), 300))
	}

	var blobs []struct {
		ContentURI     string `json:"contentUri"`
		ContentID      string `json:"contentId"`
		ContentType    string `json:"contentType"`
		ContentCreated string `json:"contentCreated"`
	}
	if err := json.Unmarshal(body, &blobs); err != nil {
		return nil, fmt.Errorf("o365 list parse: %w", err)
	}

	var all []map[string]interface{}
	var latest time.Time
	for _, b := range blobs {
		if t, err := time.Parse(time.RFC3339, b.ContentCreated); err == nil && t.After(latest) {
			latest = t
		}
		records, err := c.fetchO365Blob(ctx, token, b.ContentURI)
		if err != nil {
			continue
		}
		all = append(all, records...)
	}
	if !latest.IsZero() {
		c.cursorAdvance(cursorKey, latest)
	}
	return all, nil
}

// fetchO365Blob downloads one content blob and returns its records flattened
// into the shape detection rules in batch 4200 reference (operation_name,
// workload, user_id, client_ip, result_status).
func (c *Collector) fetchO365Blob(ctx context.Context, token, uri string) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("o365 blob: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("o365 blob returned %d", resp.StatusCode)
	}

	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("o365 blob parse: %w", err)
	}

	out := make([]map[string]interface{}, 0, len(raw))
	for _, r := range raw {
		flat := map[string]interface{}{
			"creation_time":  strOrEmpty(r, "CreationTime"),
			"id":             strOrEmpty(r, "Id"),
			"operation":      strOrEmpty(r, "Operation"),
			"organization":   strOrEmpty(r, "OrganizationId"),
			"record_type":    r["RecordType"],
			"result_status":  strOrEmpty(r, "ResultStatus"),
			"workload":       strOrEmpty(r, "Workload"),
			"user_id":        strOrEmpty(r, "UserId"),
			"user_key":       strOrEmpty(r, "UserKey"),
			"user_type":      r["UserType"],
			"client_ip":      strOrEmpty(r, "ClientIP"),
			"object_id":      strOrEmpty(r, "ObjectId"),
			"app_id":         strOrEmpty(r, "AppId"),
			"app_display":    strOrEmpty(r, "ApplicationDisplayName"),
			// Pass through the full original record so detection rules that
			// look at workload-specific nested fields (MailItemsAccessed,
			// New-InboxRule parameters, etc.) still have access.
			"raw":            r,
		}
		out = append(out, flat)
	}
	return out, nil
}
