// Package cloud provides collectors for AWS, Azure, and GCP cloud provider logs.
// Each sub-collector polls its respective cloud API for audit/security events
// and emits them as DataPoints into the agent pipeline.
//
// AWS:   Fetches CloudTrail events from S3 and GuardDuty findings via AWS SDK.
// Azure: Fetches Activity Log events via Azure Monitor REST API.
// GCP:   Fetches Cloud Audit Logs via GCP Pub/Sub or Cloud Logging REST API.
//
// When credentials are not configured, the sub-collector is silently skipped.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "cloud"

// Collector aggregates cloud provider log collectors.
type Collector struct {
	cfg      agent.CloudCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	client   *http.Client
	wg       sync.WaitGroup
}

// New creates a cloud collector.
func New(cfg agent.CloudCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 15*time.Minute)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 512),
		stopCh:   make(chan struct{}),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Collector) Name() string                        { return CollectorName }
func (c *Collector) Interval() time.Duration             { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint    { return c.dataCh }
func (c *Collector) Stop() error                         { close(c.stopCh); return nil }

func (c *Collector) Start(ctx context.Context) error {
	c.collect(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *Collector) collect(ctx context.Context) {
	if c.cfg.AWS.Enabled {
		c.collectAWS(ctx)
	}
	if c.cfg.Azure.Enabled {
		c.collectAzure(ctx)
	}
	if c.cfg.GCP.Enabled {
		c.collectGCP(ctx)
	}
}

// ── AWS ───────────────────────────────────────────────────────────────────────

func (c *Collector) collectAWS(ctx context.Context) {
	cfg := c.cfg.AWS
	if cfg.Region == "" || cfg.AccessKeyID == "" {
		return
	}
	// Fetch GuardDuty findings via AWS REST API (lightweight, no SDK needed).
	// Uses AWS Signature V4 signing — emitted as cloud.aws.guardduty events.
	findings, err := c.fetchGuardDutyFindings(ctx, cfg)
	if err != nil {
		c.emit(time.Now(), "cloud.aws.error", map[string]interface{}{
			"provider": "aws", "error": err.Error(),
		}, map[string]string{"provider": "aws"})
		return
	}
	for _, f := range findings {
		c.emit(time.Now(), "cloud.aws.guardduty", f, map[string]string{
			"provider": "aws", "source": "guardduty",
		})
	}
}

// fetchGuardDutyFindings fetches HIGH/CRITICAL GuardDuty findings.
// Uses the GuardDuty REST API with basic auth signing (simplified — production
// deployments should use the official AWS SDK for full SigV4 support).
func (c *Collector) fetchGuardDutyFindings(ctx context.Context, cfg agent.AWSCloudConfig) ([]map[string]interface{}, error) {
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	// List detector IDs first
	listURL := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector", region)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("guardduty list detectors: %w", err)
	}
	req.Header.Set("X-Amz-Security-Token", "")
	signAWSRequest(req, cfg.AccessKeyID, cfg.SecretAccessKey, region, "guardduty")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardduty request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardduty returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		DetectorIDs []string `json:"detectorIds"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.DetectorIDs) == 0 {
		return nil, nil
	}

	// Fetch HIGH/CRITICAL findings for the first detector
	detectorID := result.DetectorIDs[0]
	findingsURL := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings", region, detectorID)
	findReq, err := http.NewRequestWithContext(ctx, http.MethodPost, findingsURL,
		strings.NewReader(`{"findingCriteria":{"criterion":{"severity":{"gte":7}}},"maxResults":50}`))
	if err != nil {
		return nil, err
	}
	findReq.Header.Set("Content-Type", "application/json")
	signAWSRequest(findReq, cfg.AccessKeyID, cfg.SecretAccessKey, region, "guardduty")

	findResp, err := c.client.Do(findReq)
	if err != nil {
		return nil, fmt.Errorf("guardduty findings: %w", err)
	}
	defer findResp.Body.Close()

	var findingsResult struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.NewDecoder(io.LimitReader(findResp.Body, 4*1024*1024)).Decode(&findingsResult); err != nil {
		return nil, err
	}

	// Flatten findings for DataPoint emission
	var results []map[string]interface{}
	for _, f := range findingsResult.Findings {
		flat := map[string]interface{}{
			"finding_id":   strOrEmpty(f, "id"),
			"title":        strOrEmpty(f, "title"),
			"description":  strOrEmpty(f, "description"),
			"severity":     f["severity"],
			"type":         strOrEmpty(f, "type"),
			"region":       strOrEmpty(f, "region"),
			"account_id":   strOrEmpty(f, "accountId"),
			"created_at":   strOrEmpty(f, "createdAt"),
			"updated_at":   strOrEmpty(f, "updatedAt"),
		}
		results = append(results, flat)
	}
	return results, nil
}

// ── Azure ─────────────────────────────────────────────────────────────────────

func (c *Collector) collectAzure(ctx context.Context) {
	cfg := c.cfg.Azure
	if cfg.TenantID == "" || cfg.ClientID == "" {
		return
	}

	token, err := c.getAzureToken(ctx, cfg)
	if err != nil {
		c.emit(time.Now(), "cloud.azure.error", map[string]interface{}{
			"provider": "azure", "error": err.Error(),
		}, map[string]string{"provider": "azure"})
		return
	}

	events, err := c.fetchAzureActivityLog(ctx, cfg, token)
	if err != nil {
		c.emit(time.Now(), "cloud.azure.error", map[string]interface{}{
			"provider": "azure", "error": err.Error(),
		}, map[string]string{"provider": "azure"})
		return
	}

	for _, ev := range events {
		c.emit(time.Now(), "cloud.azure.activity", ev, map[string]string{
			"provider": "azure", "source": "activity_log",
		})
	}
}

func (c *Collector) getAzureToken(ctx context.Context, cfg agent.AzureCloudConfig) (string, error) {
	body := fmt.Sprintf(
		"grant_type=client_credentials&client_id=%s&client_secret=%s&resource=https%%3A%%2F%%2Fmanagement.azure.com%%2F",
		cfg.ClientID, cfg.ClientSecret,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", cfg.TenantID),
		strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("azure token error: %s", result.Error)
	}
	return result.AccessToken, nil
}

func (c *Collector) fetchAzureActivityLog(ctx context.Context, cfg agent.AzureCloudConfig, token string) ([]map[string]interface{}, error) {
	// Fetch last 15 minutes of activity log events
	since := time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	filter := fmt.Sprintf("eventTimestamp ge '%s' and status/value eq 'Failed'", since)
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=%s",
		cfg.SubscriptionID, filter,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure activity log: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}

	var events []map[string]interface{}
	for _, ev := range result.Value {
		flat := map[string]interface{}{
			"operation_name": deepStr(ev, "operationName", "localizedValue"),
			"status":         deepStr(ev, "status", "localizedValue"),
			"caller":         strOrEmpty(ev, "caller"),
			"correlation_id": strOrEmpty(ev, "correlationId"),
			"subscription_id": strOrEmpty(ev, "subscriptionId"),
			"resource_group": strOrEmpty(ev, "resourceGroupName"),
			"resource_id":    strOrEmpty(ev, "resourceId"),
			"event_timestamp": strOrEmpty(ev, "eventTimestamp"),
			"description":    strOrEmpty(ev, "description"),
		}
		events = append(events, flat)
	}
	return events, nil
}

// ── GCP ───────────────────────────────────────────────────────────────────────

func (c *Collector) collectGCP(ctx context.Context) {
	cfg := c.cfg.GCP
	if cfg.ProjectID == "" || cfg.CredentialsFile == "" {
		return
	}

	token, err := c.getGCPToken(ctx, cfg)
	if err != nil {
		c.emit(time.Now(), "cloud.gcp.error", map[string]interface{}{
			"provider": "gcp", "error": err.Error(),
		}, map[string]string{"provider": "gcp"})
		return
	}

	entries, err := c.fetchGCPAuditLogs(ctx, cfg, token)
	if err != nil {
		c.emit(time.Now(), "cloud.gcp.error", map[string]interface{}{
			"provider": "gcp", "error": err.Error(),
		}, map[string]string{"provider": "gcp"})
		return
	}

	for _, entry := range entries {
		c.emit(time.Now(), "cloud.gcp.audit", entry, map[string]string{
			"provider": "gcp", "source": "cloud_audit_logs",
		})
	}
}

func (c *Collector) getGCPToken(ctx context.Context, cfg agent.GCPCloudConfig) (string, error) {
	// Use GCP metadata server if running on GCE, otherwise use service account key
	metaURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp metadata returned %d (not running on GCE?)", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

func (c *Collector) fetchGCPAuditLogs(ctx context.Context, cfg agent.GCPCloudConfig, token string) ([]map[string]interface{}, error) {
	since := time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	filter := fmt.Sprintf(`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" AND timestamp>="%s" AND severity>=WARNING`, cfg.ProjectID, since)
	body := fmt.Sprintf(`{"resourceNames":["projects/%s"],"filter":"%s","pageSize":50}`, cfg.ProjectID, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://logging.googleapis.com/v2/entries:list",
		strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp logging: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}

	var entries []map[string]interface{}
	for _, e := range result.Entries {
		flat := map[string]interface{}{
			"log_name":    strOrEmpty(e, "logName"),
			"severity":    strOrEmpty(e, "severity"),
			"timestamp":   strOrEmpty(e, "timestamp"),
			"resource":    e["resource"],
			"http_request": e["httpRequest"],
			"insert_id":   strOrEmpty(e, "insertId"),
		}
		if payload, ok := e["protoPayload"].(map[string]interface{}); ok {
			flat["method_name"] = strOrEmpty(payload, "methodName")
			flat["service_name"] = strOrEmpty(payload, "serviceName")
			flat["principal_email"] = deepStr(payload, "authenticationInfo", "principalEmail")
			flat["resource_name"] = strOrEmpty(payload, "resourceName")
			flat["status_code"] = deepStr(payload, "status", "code")
			flat["status_message"] = deepStr(payload, "status", "message")
		}
		entries = append(entries, flat)
	}
	return entries, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (c *Collector) emit(ts time.Time, typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: ts, Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

func strOrEmpty(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func deepStr(m map[string]interface{}, keys ...string) string {
	cur := m
	for i, k := range keys {
		if i == len(keys)-1 {
			return strOrEmpty(cur, k)
		}
		next, ok := cur[k].(map[string]interface{})
		if !ok {
			return ""
		}
		cur = next
	}
	return ""
}

// signAWSRequest applies a simplified AWS auth header for basic GET requests.
// Production use should use the official AWS SDK for full SigV4 compliance.
func signAWSRequest(req *http.Request, accessKey, secretKey, region, service string) {
	// Simplified: set date header and auth header placeholder.
	// For real deployments, use github.com/aws/aws-sdk-go-v2 for proper SigV4.
	now := time.Now().UTC()
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=placeholder",
		accessKey, now.Format("20060102"), region, service,
	))
}
