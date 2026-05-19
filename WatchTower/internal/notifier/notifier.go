// Package notifier sends alert notifications to external systems (Slack,
// Microsoft Teams, generic webhooks, email) when high-severity alerts fire.
//
// Notifications are filtered by minimum severity level and rate-limited per
// destination to prevent alert storms. All sends are async and non-blocking
// so notification failures never block the engine.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// Destination is an alias to config.NotifierDestination so callers in this
// package can stay terse while sharing the canonical YAML/JSON shape.
type Destination = config.NotifierDestination

// Config is an alias to config.NotifierConfig.
type Config = config.NotifierConfig

// Notifier implements engine.RBAHook so alerts auto-fire as they're stored.
type Notifier struct {
	cfg    Config
	logger *zap.Logger
	client *http.Client

	mu         sync.Mutex
	rateBuckets map[string]*rateBucket // key = "type:url"
}

type rateBucket struct {
	tokens   int
	lastFill time.Time
}

// New returns a notifier ready to be attached as an RBAHook.
func New(cfg Config, logger *zap.Logger) *Notifier {
	if cfg.RatePerDestPerMinute <= 0 {
		cfg.RatePerDestPerMinute = 30
	}
	return &Notifier{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
		rateBuckets: make(map[string]*rateBucket),
	}
}

// OnAlert implements engine.RBAHook. It fires asynchronously for every
// stored alert; destinations filter by min_level themselves.
func (n *Notifier) OnAlert(alert *models.Alert, event *models.Event) {
	if !n.cfg.Enabled || alert == nil {
		return
	}
	go n.dispatch(alert)
}

// NotifyAgentDisconnect fires an asynchronous notification to all enabled
// destinations when an agent transitions from active/streaming to disconnected.
// It bypasses the min_level filter so the message always reaches destinations
// (agent health is separate from alert severity).
func (n *Notifier) NotifyAgentDisconnect(agent *models.Agent) {
	if !n.cfg.Enabled || agent == nil {
		return
	}
	go n.dispatchDisconnect(agent)
}

func (n *Notifier) dispatchDisconnect(agent *models.Agent) {
	lastSeen := time.UnixMilli(agent.LastHeartbeat)
	ago := time.Since(lastSeen).Round(time.Second)
	title := fmt.Sprintf("Agent disconnected: %s", agent.Hostname)
	body := fmt.Sprintf(
		"Agent ID: %s\nHostname: %s\nLast heartbeat: %s (%s ago)",
		agent.ID, agent.Hostname,
		lastSeen.UTC().Format(time.RFC3339), ago,
	)

	for _, dest := range n.cfg.Destinations {
		if !dest.Enabled {
			continue
		}
		if !n.allowSend(dest.Type + ":" + dest.URL) {
			n.logger.Warn("notifier rate-limited (disconnect)",
				zap.String("dest_type", dest.Type),
				zap.String("agent_id", agent.ID),
			)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err error
		switch dest.Type {
		case "slack":
			err = n.sendSlackText(ctx, dest, title, body, "#6c757d")
		case "teams":
			err = n.sendTeamsText(ctx, dest, title, body, "6c757d")
		case "webhook":
			payload := map[string]interface{}{
				"event":          "agent_disconnected",
				"agent_id":       agent.ID,
				"hostname":       agent.Hostname,
				"last_heartbeat": agent.LastHeartbeat,
				"ago_seconds":    int(ago.Seconds()),
			}
			err = n.postJSON(ctx, dest.URL, payload)
		case "email":
			err = n.sendEmailText(dest, title, body)
		default:
			err = fmt.Errorf("unknown destination type: %s", dest.Type)
		}
		cancel()
		if err != nil {
			n.logger.Warn("notifier dispatch failed (disconnect)",
				zap.String("dest_type", dest.Type),
				zap.String("agent_id", agent.ID),
				zap.Error(err),
			)
		}
	}
}

func (n *Notifier) sendSlackText(ctx context.Context, dest Destination, title, body, color string) error {
	payload := map[string]interface{}{
		"text": title,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  title,
				"text":   body,
				"footer": "Sentinel SIEM",
			},
		},
	}
	return n.postJSON(ctx, dest.URL, payload)
}

func (n *Notifier) sendTeamsText(ctx context.Context, dest Destination, title, body, color string) error {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": color,
		"summary":    title,
		"title":      title,
		"text":       body,
	}
	return n.postJSON(ctx, dest.URL, payload)
}

func (n *Notifier) sendEmailText(dest Destination, subject, body string) error {
	if dest.SMTPHost == "" || dest.From == "" || len(dest.To) == 0 {
		return fmt.Errorf("email destination missing required fields")
	}
	if dest.SMTPPort == 0 {
		dest.SMTPPort = 587
	}
	addr := fmt.Sprintf("%s:%d", dest.SMTPHost, dest.SMTPPort)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: [Sentinel SIEM] %s\r\n\r\n%s",
		dest.From, strings.Join(dest.To, ", "), subject, body)
	var auth smtp.Auth
	if dest.SMTPUser != "" {
		auth = smtp.PlainAuth("", dest.SMTPUser, dest.SMTPPass, dest.SMTPHost)
	}
	return smtp.SendMail(addr, auth, dest.From, dest.To, []byte(msg))
}

func (n *Notifier) dispatch(alert *models.Alert) {
	for _, dest := range n.cfg.Destinations {
		if !dest.Enabled || alert.Level < dest.MinLevel {
			continue
		}
		if !n.allowSend(dest.Type + ":" + dest.URL) {
			n.logger.Warn("notifier rate-limited",
				zap.String("dest_type", dest.Type),
				zap.Int("level", alert.Level),
			)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var err error
		switch dest.Type {
		case "slack":
			err = n.sendSlack(ctx, dest, alert)
		case "teams":
			err = n.sendTeams(ctx, dest, alert)
		case "webhook":
			err = n.sendGenericWebhook(ctx, dest, alert)
		case "email":
			err = n.sendEmail(dest, alert)
		default:
			err = fmt.Errorf("unknown destination type: %s", dest.Type)
		}
		cancel()
		if err != nil {
			n.logger.Warn("notifier dispatch failed",
				zap.String("dest_type", dest.Type),
				zap.Error(err),
			)
		}
	}
}

// allowSend implements per-destination token bucket rate limiting.
// Buckets refill at cfg.RatePerDestPerMinute tokens per minute.
func (n *Notifier) allowSend(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	b, ok := n.rateBuckets[key]
	if !ok {
		b = &rateBucket{tokens: n.cfg.RatePerDestPerMinute, lastFill: now}
		n.rateBuckets[key] = b
	}
	// Refill
	elapsedMin := now.Sub(b.lastFill).Minutes()
	if elapsedMin > 0 {
		add := int(elapsedMin * float64(n.cfg.RatePerDestPerMinute))
		if add > 0 {
			b.tokens += add
			if b.tokens > n.cfg.RatePerDestPerMinute {
				b.tokens = n.cfg.RatePerDestPerMinute
			}
			b.lastFill = now
		}
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// ── Slack ────────────────────────────────────────────────────────────────────

func (n *Notifier) sendSlack(ctx context.Context, dest Destination, alert *models.Alert) error {
	color := severityColor(alert.Level)
	payload := map[string]interface{}{
		"text": fmt.Sprintf("Sentinel alert: %s", alert.Title),
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  alert.Title,
				"text":   alert.Description,
				"fields": []map[string]interface{}{
					{"title": "Severity", "value": fmt.Sprintf("%d", alert.Level), "short": true},
					{"title": "Rule ID", "value": fmt.Sprintf("%d", alert.RuleID), "short": true},
					{"title": "Agent", "value": alert.AgentID, "short": true},
					{"title": "Time", "value": time.UnixMilli(alert.Timestamp).Format(time.RFC3339), "short": true},
				},
				"footer":      "Sentinel SIEM",
				"footer_icon": "",
				"ts":          alert.Timestamp / 1000,
			},
		},
	}
	return n.postJSON(ctx, dest.URL, payload)
}

// ── Microsoft Teams ──────────────────────────────────────────────────────────

func (n *Notifier) sendTeams(ctx context.Context, dest Destination, alert *models.Alert) error {
	color := severityColor(alert.Level)
	if strings.HasPrefix(color, "#") {
		color = strings.TrimPrefix(color, "#")
	}
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": color,
		"summary":    alert.Title,
		"title":      fmt.Sprintf("[Severity %d] %s", alert.Level, alert.Title),
		"sections": []map[string]interface{}{
			{
				"activityTitle":    alert.Title,
				"activitySubtitle": fmt.Sprintf("Agent %s · Rule %d", alert.AgentID, alert.RuleID),
				"text":             alert.Description,
				"facts": []map[string]string{
					{"name": "Severity", "value": fmt.Sprintf("%d", alert.Level)},
					{"name": "Rule ID", "value": fmt.Sprintf("%d", alert.RuleID)},
					{"name": "Agent", "value": alert.AgentID},
					{"name": "Time", "value": time.UnixMilli(alert.Timestamp).Format(time.RFC3339)},
				},
			},
		},
	}
	return n.postJSON(ctx, dest.URL, payload)
}

// ── Generic Webhook ──────────────────────────────────────────────────────────

func (n *Notifier) sendGenericWebhook(ctx context.Context, dest Destination, alert *models.Alert) error {
	return n.postJSON(ctx, dest.URL, alert)
}

// ── Email ────────────────────────────────────────────────────────────────────

func (n *Notifier) sendEmail(dest Destination, alert *models.Alert) error {
	if dest.SMTPHost == "" || dest.From == "" || len(dest.To) == 0 {
		return fmt.Errorf("email destination missing required fields")
	}
	if dest.SMTPPort == 0 {
		dest.SMTPPort = 587
	}
	addr := fmt.Sprintf("%s:%d", dest.SMTPHost, dest.SMTPPort)

	subject := fmt.Sprintf("[Sentinel SIEM][L%d] %s", alert.Level, alert.Title)
	body := fmt.Sprintf(
		"Severity: %d\nRule ID: %d\nAgent: %s\nTime: %s\n\n%s\n\nDescription:\n%s\n",
		alert.Level, alert.RuleID, alert.AgentID,
		time.UnixMilli(alert.Timestamp).Format(time.RFC3339),
		alert.Title, alert.Description,
	)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		dest.From, strings.Join(dest.To, ", "), subject, body)

	var auth smtp.Auth
	if dest.SMTPUser != "" {
		auth = smtp.PlainAuth("", dest.SMTPUser, dest.SMTPPass, dest.SMTPHost)
	}
	return smtp.SendMail(addr, auth, dest.From, dest.To, []byte(msg))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (n *Notifier) postJSON(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// severityColor maps alert level to a hex color (used by Slack & Teams).
func severityColor(level int) string {
	switch {
	case level >= 13:
		return "#dc3545" // red (critical)
	case level >= 10:
		return "#fd7e14" // orange (high)
	case level >= 7:
		return "#ffc107" // yellow (medium)
	default:
		return "#28a745" // green (low/info)
	}
}
