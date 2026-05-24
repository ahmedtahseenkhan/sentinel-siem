// Package cloud provides collectors for AWS, Azure, and GCP cloud provider logs.
// Each sub-collector polls its respective cloud API for audit/security events
// and emits them as DataPoints into the agent pipeline.
//
// AWS:   GuardDuty findings + CloudTrail JSON.gz objects from S3.
// Azure: Activity Log events via Azure Monitor REST API.
// GCP:   Cloud Audit Logs via Cloud Logging REST API.
//
// When credentials are not configured, the sub-collector is silently skipped.
package cloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

	// cursors holds the high-water mark per provider so each poll fetches
	// only events newer than what we already emitted, preventing duplicates
	// and avoiding the prior "always last 15m" race condition.
	cursorMu sync.Mutex
	cursors  map[string]time.Time

	// seenS3Objects tracks CloudTrail S3 keys already processed within this
	// process. Prevents re-emitting the same gzipped log file on every poll
	// (S3 keys are monotonic enough that this map stays bounded for hours;
	// for long-running agents the cursor by LastModified is the real defense).
	seenS3Mu sync.Mutex
	seenS3   map[string]struct{}
}

// New creates a cloud collector.
func New(cfg agent.CloudCollectorConfig) *Collector {
	interval := agent.ParseDuration(cfg.Interval, 15*time.Minute)
	return &Collector{
		cfg:      cfg,
		interval: interval,
		dataCh:   make(chan models.DataPoint, 512),
		stopCh:   make(chan struct{}),
		client:   &http.Client{Timeout: 60 * time.Second},
		cursors:  make(map[string]time.Time),
		seenS3:   make(map[string]struct{}),
	}
}

func (c *Collector) Name() string                     { return CollectorName }
func (c *Collector) Interval() time.Duration          { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }
func (c *Collector) Stop() error                      { close(c.stopCh); return nil }

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
	if c.cfg.O365.Enabled {
		c.collectO365(ctx)
	}
	if c.cfg.Workspace.Enabled {
		c.collectWorkspace(ctx)
	}
	if c.cfg.Defender.Enabled {
		c.collectDefender(ctx)
	}
}

// cursorSince returns the high-water mark for provider, defaulting to
// (now - interval) on first run so we don't replay all of history.
func (c *Collector) cursorSince(provider string) time.Time {
	c.cursorMu.Lock()
	defer c.cursorMu.Unlock()
	if t, ok := c.cursors[provider]; ok {
		return t
	}
	return time.Now().Add(-c.interval)
}

func (c *Collector) cursorAdvance(provider string, t time.Time) {
	c.cursorMu.Lock()
	defer c.cursorMu.Unlock()
	if cur, ok := c.cursors[provider]; !ok || t.After(cur) {
		c.cursors[provider] = t
	}
}

// ── AWS ───────────────────────────────────────────────────────────────────────

func (c *Collector) collectAWS(ctx context.Context) {
	cfg := c.cfg.AWS
	if cfg.Region == "" || cfg.AccessKeyID == "" {
		return
	}

	// GuardDuty findings (real SigV4 now).
	if findings, err := c.fetchGuardDutyFindings(ctx, cfg); err != nil {
		c.emit(time.Now(), "cloud.aws.error", map[string]interface{}{
			"provider": "aws", "source": "guardduty", "error": err.Error(),
		}, map[string]string{"provider": "aws"})
	} else {
		for _, f := range findings {
			c.emit(time.Now(), "cloud.aws.guardduty", f, map[string]string{
				"provider": "aws", "source": "guardduty",
			})
		}
	}

	// CloudTrail S3 objects (newly added).
	if cfg.CloudTrailBucket != "" {
		if events, err := c.fetchCloudTrailFromS3(ctx, cfg); err != nil {
			c.emit(time.Now(), "cloud.aws.error", map[string]interface{}{
				"provider": "aws", "source": "cloudtrail", "error": err.Error(),
			}, map[string]string{"provider": "aws"})
		} else {
			for _, ev := range events {
				c.emit(time.Now(), "cloud.aws.cloudtrail", ev, map[string]string{
					"provider": "aws", "source": "cloudtrail",
				})
			}
		}
	}
}

func (c *Collector) fetchGuardDutyFindings(ctx context.Context, cfg agent.AWSCloudConfig) ([]map[string]interface{}, error) {
	region := cfg.Region
	if cfg.GuardDutyRegion != "" {
		region = cfg.GuardDutyRegion
	}

	// List detector IDs.
	listURL := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector", region)
	listReq, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	signAWSRequestV4(listReq, cfg.AccessKeyID, cfg.SecretAccessKey, region, "guardduty")
	listResp, err := c.client.Do(listReq)
	if err != nil {
		return nil, fmt.Errorf("guardduty list: %w", err)
	}
	defer listResp.Body.Close()
	listBody, _ := io.ReadAll(io.LimitReader(listResp.Body, 1*1024*1024))
	if listResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardduty list returned %d: %s", listResp.StatusCode, string(listBody))
	}
	var listResult struct {
		DetectorIDs []string `json:"detectorIds"`
	}
	if err := json.Unmarshal(listBody, &listResult); err != nil || len(listResult.DetectorIDs) == 0 {
		return nil, nil
	}

	detectorID := listResult.DetectorIDs[0]
	findingsURL := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings", region, detectorID)
	body := `{"findingCriteria":{"criterion":{"severity":{"gte":7}}},"maxResults":50}`
	findReq, err := http.NewRequestWithContext(ctx, http.MethodPost, findingsURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	findReq.Header.Set("Content-Type", "application/json")
	signAWSRequestV4(findReq, cfg.AccessKeyID, cfg.SecretAccessKey, region, "guardduty")

	resp, err := c.client.Do(findReq)
	if err != nil {
		return nil, fmt.Errorf("guardduty findings: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("guardduty findings returned %d: %s", resp.StatusCode, string(respBody))
	}
	var findingsResult struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(respBody, &findingsResult); err != nil {
		return nil, err
	}
	var results []map[string]interface{}
	for _, f := range findingsResult.Findings {
		results = append(results, map[string]interface{}{
			"finding_id":  strOrEmpty(f, "id"),
			"title":       strOrEmpty(f, "title"),
			"description": strOrEmpty(f, "description"),
			"severity":    f["severity"],
			"type":        strOrEmpty(f, "type"),
			"region":      strOrEmpty(f, "region"),
			"account_id":  strOrEmpty(f, "accountId"),
			"created_at":  strOrEmpty(f, "createdAt"),
			"updated_at":  strOrEmpty(f, "updatedAt"),
		})
	}
	return results, nil
}

// fetchCloudTrailFromS3 lists newly-uploaded CloudTrail JSON.gz objects from
// the configured S3 bucket and emits each Record as a flat event. Uses the
// high-water mark cursor on LastModified to avoid re-processing.
func (c *Collector) fetchCloudTrailFromS3(ctx context.Context, cfg agent.AWSCloudConfig) ([]map[string]interface{}, error) {
	since := c.cursorSince("aws.cloudtrail")
	// CloudTrail S3 keys follow:
	//   AWSLogs/<accountId>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz
	// We list under the date-based prefix for "today" to keep the response small.
	prefix := fmt.Sprintf("AWSLogs/")

	keys, latest, err := c.listS3Bucket(ctx, cfg, prefix, since)
	if err != nil {
		return nil, err
	}
	var all []map[string]interface{}
	for _, key := range keys {
		c.seenS3Mu.Lock()
		_, seen := c.seenS3[key]
		c.seenS3Mu.Unlock()
		if seen {
			continue
		}
		events, err := c.fetchAndParseS3Object(ctx, cfg, key)
		if err != nil {
			continue
		}
		all = append(all, events...)
		c.seenS3Mu.Lock()
		c.seenS3[key] = struct{}{}
		// Bound the seen map; cursor remains the real defense across restarts.
		if len(c.seenS3) > 10000 {
			for k := range c.seenS3 {
				delete(c.seenS3, k)
				if len(c.seenS3) < 5000 {
					break
				}
			}
		}
		c.seenS3Mu.Unlock()
	}
	if !latest.IsZero() {
		c.cursorAdvance("aws.cloudtrail", latest)
	}
	return all, nil
}

// listS3Bucket returns S3 keys with LastModified > since, and the maximum
// LastModified seen. Uses S3 ListObjectsV2.
func (c *Collector) listS3Bucket(ctx context.Context, cfg agent.AWSCloudConfig, prefix string, since time.Time) ([]string, time.Time, error) {
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", cfg.CloudTrailBucket, cfg.Region)
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("prefix", prefix)
	q.Set("max-keys", "1000")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	signAWSRequestV4(req, cfg.AccessKeyID, cfg.SecretAccessKey, cfg.Region, "s3")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("s3 list: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("s3 list returned %d: %s", resp.StatusCode, snippet(string(body), 300))
	}
	// Light XML parse: we only need <Key>...</Key> and <LastModified>...</LastModified>
	// in document order, paired by occurrence within each <Contents>.
	keys, latest := parseS3ListXML(string(body), since)
	return keys, latest, nil
}

func parseS3ListXML(xmlStr string, since time.Time) (keys []string, latest time.Time) {
	pos := 0
	for {
		i := strings.Index(xmlStr[pos:], "<Contents>")
		if i == -1 {
			break
		}
		i += pos
		end := strings.Index(xmlStr[i:], "</Contents>")
		if end == -1 {
			break
		}
		entry := xmlStr[i : i+end]
		key := xmlInner(entry, "Key")
		modStr := xmlInner(entry, "LastModified")
		pos = i + end + len("</Contents>")
		if key == "" || modStr == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, modStr)
		if err != nil {
			continue
		}
		if !t.After(since) {
			continue
		}
		keys = append(keys, key)
		if t.After(latest) {
			latest = t
		}
	}
	return
}

func xmlInner(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	i := strings.Index(xml, open)
	if i == -1 {
		return ""
	}
	rest := xml[i+len(open):]
	j := strings.Index(rest, close)
	if j == -1 {
		return ""
	}
	return rest[:j]
}

// fetchAndParseS3Object downloads one CloudTrail .json.gz, gunzips, parses,
// returns the Records flattened.
func (c *Collector) fetchAndParseS3Object(ctx context.Context, cfg agent.AWSCloudConfig, key string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", cfg.CloudTrailBucket, cfg.Region, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	signAWSRequestV4(req, cfg.AccessKeyID, cfg.SecretAccessKey, cfg.Region, "s3")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 get %s: %w", key, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("s3 get %s returned %d: %s", key, resp.StatusCode, string(body))
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(key, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", key, err)
		}
		defer gz.Close()
		reader = gz
	}

	var parsed struct {
		Records []map[string]interface{} `json:"Records"`
	}
	if err := json.NewDecoder(io.LimitReader(reader, 32*1024*1024)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}

	var out []map[string]interface{}
	for _, r := range parsed.Records {
		out = append(out, map[string]interface{}{
			"event_time":   strOrEmpty(r, "eventTime"),
			"event_name":   strOrEmpty(r, "eventName"),
			"event_source": strOrEmpty(r, "eventSource"),
			"aws_region":   strOrEmpty(r, "awsRegion"),
			"source_ip":    strOrEmpty(r, "sourceIPAddress"),
			"user_agent":   strOrEmpty(r, "userAgent"),
			"user_identity": r["userIdentity"],
			"error_code":   strOrEmpty(r, "errorCode"),
			"error_message": strOrEmpty(r, "errorMessage"),
			"request_parameters": r["requestParameters"],
			"response_elements":  r["responseElements"],
			"recipient_account_id": strOrEmpty(r, "recipientAccountId"),
		})
	}
	return out, nil
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
	return c.getAzureTokenForResource(ctx, cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
		"https://management.azure.com/")
}

// getAzureTokenForResource is the generic Azure client-credentials OAuth
// exchange parameterised by audience/resource. Used by:
//   - collectAzure                  (resource = management.azure.com)
//   - collectO365 / Defender Graph  (resource = manage.office.com /
//                                    graph.microsoft.com)
//
// Centralised so all Azure-family sources share the same retry, error
// shape, and v1.0-vs-v2.0 endpoint choice. We stay on v1.0 because
// resource= is the only parameter format that works for the legacy
// O365 Management Activity API; Graph endpoints accept both.
func (c *Collector) getAzureTokenForResource(ctx context.Context, tenantID, clientID, clientSecret, resource string) (string, error) {
	body := fmt.Sprintf(
		"grant_type=client_credentials&client_id=%s&client_secret=%s&resource=%s",
		clientID, clientSecret, url.QueryEscape(resource),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID),
		strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("azure token error: %s — %s", result.Error, result.ErrorDescription)
	}
	return result.AccessToken, nil
}

func (c *Collector) fetchAzureActivityLog(ctx context.Context, cfg agent.AzureCloudConfig, token string) ([]map[string]interface{}, error) {
	since := c.cursorSince("azure.activity")
	// Filter no longer hard-codes status=Failed; that hid the majority of
	// suspicious *successful* operations (role grants, resource creation)
	// which detection rules need to see. If operators want failures only,
	// they can configure it via a future field; for now we take everything
	// in the window.
	filter := fmt.Sprintf("eventTimestamp ge '%s'", since.UTC().Format(time.RFC3339))
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&result); err != nil {
		return nil, err
	}

	var latest time.Time
	var events []map[string]interface{}
	for _, ev := range result.Value {
		ts := strOrEmpty(ev, "eventTimestamp")
		if t, err := time.Parse(time.RFC3339, ts); err == nil && t.After(latest) {
			latest = t
		}
		events = append(events, map[string]interface{}{
			"operation_name":  deepStr(ev, "operationName", "localizedValue"),
			"status":          deepStr(ev, "status", "localizedValue"),
			"caller":          strOrEmpty(ev, "caller"),
			"correlation_id":  strOrEmpty(ev, "correlationId"),
			"subscription_id": strOrEmpty(ev, "subscriptionId"),
			"resource_group":  strOrEmpty(ev, "resourceGroupName"),
			"resource_id":     strOrEmpty(ev, "resourceId"),
			"event_timestamp": ts,
			"description":     strOrEmpty(ev, "description"),
		})
	}
	if !latest.IsZero() {
		c.cursorAdvance("azure.activity", latest)
	}
	return events, nil
}

// ── GCP ───────────────────────────────────────────────────────────────────────

func (c *Collector) collectGCP(ctx context.Context) {
	cfg := c.cfg.GCP
	if cfg.ProjectID == "" {
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

// getGCPToken supports both auth modes:
//  1. CredentialsFile set: exchange a service-account JWT for an access token
//     (works anywhere — agents on-prem, AWS, laptops).
//  2. CredentialsFile empty: fall back to the GCE metadata server (works only
//     when WatchNode runs inside Google Cloud).
//
// Previously only mode 2 was implemented, which silently broke every
// non-GCE deployment — exactly the case where you most want central
// CSPM signal in your SIEM.
func (c *Collector) getGCPToken(ctx context.Context, cfg agent.GCPCloudConfig) (string, error) {
	if cfg.CredentialsFile != "" {
		return c.getGCPTokenFromKey(ctx, cfg.CredentialsFile)
	}
	return c.getGCPTokenFromMetadata(ctx)
}

func (c *Collector) getGCPTokenFromMetadata(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("gcp metadata returned %d (not running on GCE? set credentials_file in config)", resp.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

type gcpKeyFile struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

func (c *Collector) getGCPTokenFromKey(ctx context.Context, path string) (string, error) {
	return c.getGCPTokenScoped(ctx, path, []string{
		"https://www.googleapis.com/auth/logging.read",
		"https://www.googleapis.com/auth/cloud-platform.read-only",
	}, "")
}

// getGCPTokenScoped is the generic service-account JWT exchange. Lets each
// caller specify the OAuth scopes it needs and, optionally, a `subject` to
// impersonate via domain-wide delegation (required for Workspace Admin
// Reports — the SA must have DWD enabled and `subject` set to an admin
// email in the target Workspace tenant).
func (c *Collector) getGCPTokenScoped(ctx context.Context, path string, scopes []string, subject string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read gcp key file: %w", err)
	}
	var key gcpKeyFile
	if err := json.Unmarshal(data, &key); err != nil {
		return "", fmt.Errorf("parse gcp key file: %w", err)
	}
	if key.ClientEmail == "" || key.PrivateKey == "" {
		return "", fmt.Errorf("gcp key file missing client_email or private_key")
	}
	tokenURI := key.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	now := time.Now().Unix()
	header := base64URL([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"iss":   key.ClientEmail,
		"scope": strings.Join(scopes, " "),
		"aud":   tokenURI,
		"exp":   now + 3600,
		"iat":   now,
	}
	if subject != "" {
		claims["sub"] = subject
	}
	claimsJSON, _ := json.Marshal(claims)
	claimsEnc := base64URL(claimsJSON)
	signingInput := header + "." + claimsEnc

	priv, err := parseRSAPrivateKey(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse gcp private key: %w", err)
	}
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	jwt := signingInput + "." + base64URL(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp token exchange returned %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("gcp token exchange: %s %s", out.Error, out.ErrorDesc)
	}
	return out.AccessToken, nil
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key")
	}
	return rsaKey, nil
}

func (c *Collector) fetchGCPAuditLogs(ctx context.Context, cfg agent.GCPCloudConfig, token string) ([]map[string]interface{}, error) {
	since := c.cursorSince("gcp.audit")
	filter := fmt.Sprintf(
		`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" AND timestamp>="%s" AND severity>=WARNING`,
		cfg.ProjectID, since.UTC().Format(time.RFC3339),
	)
	body := fmt.Sprintf(`{"resourceNames":["projects/%s"],"filter":"%s","pageSize":1000}`, cfg.ProjectID, filter)

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
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp logging returned %d: %s", resp.StatusCode, snippet(string(respBody), 300))
	}

	var result struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	var latest time.Time
	var entries []map[string]interface{}
	for _, e := range result.Entries {
		ts := strOrEmpty(e, "timestamp")
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && t.After(latest) {
			latest = t
		}
		flat := map[string]interface{}{
			"log_name":     strOrEmpty(e, "logName"),
			"severity":     strOrEmpty(e, "severity"),
			"timestamp":    ts,
			"resource":     e["resource"],
			"http_request": e["httpRequest"],
			"insert_id":    strOrEmpty(e, "insertId"),
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
	if !latest.IsZero() {
		c.cursorAdvance("gcp.audit", latest)
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

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Compile-time guard so the new bytes-using imports are referenced even if
// future refactors remove the body reader path.
var _ = bytes.NewReader
