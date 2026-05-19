package index

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/watchvault/watchvault/internal/config"
	"github.com/watchvault/watchvault/internal/opensearch"
	"go.uber.org/zap"
)

//go:embed templates/*.json
var templateFS embed.FS

//go:embed lifecycle/*.json
var lifecycleFS embed.FS

type Manager struct {
	client *opensearch.Client
	cfg    config.IndicesConfig
	logger *zap.Logger
}

func NewManager(client *opensearch.Client, cfg config.IndicesConfig, logger *zap.Logger) *Manager {
	return &Manager{client: client, cfg: cfg, logger: logger}
}

func (m *Manager) SetupTemplates() error {
	templates := []string{
		"watchvault-alerts",
		"watchvault-events",
		"watchvault-fim",
		"watchvault-vulnerability",
		"watchvault-system",
		"watchvault-audit",
	}

	for _, name := range templates {
		data, err := templateFS.ReadFile("templates/" + name + ".json")
		if err != nil {
			m.logger.Warn("template file not found", zap.String("name", name), zap.Error(err))
			continue
		}
		var body map[string]interface{}
		if err := json.Unmarshal(data, &body); err != nil {
			m.logger.Warn("invalid template json", zap.String("name", name), zap.Error(err))
			continue
		}

		if tmpl, ok := body["template"].(map[string]interface{}); ok {
			if settings, ok := tmpl["settings"].(map[string]interface{}); ok {
				if m.cfg.Shards > 0 {
					settings["number_of_shards"] = m.cfg.Shards
				}
				if m.cfg.Replicas >= 0 {
					settings["number_of_replicas"] = m.cfg.Replicas
				}
			}
		}

		if m.cfg.Prefix != "" && m.cfg.Prefix != "watchvault" {
			if patterns, ok := body["index_patterns"].([]interface{}); ok {
				for i, p := range patterns {
					if ps, ok := p.(string); ok {
						patterns[i] = strings.Replace(ps, "watchvault", m.cfg.Prefix, 1)
					}
				}
			}
		}

		if err := m.client.PutIndexTemplate(name, body); err != nil {
			m.logger.Error("failed to create template", zap.String("name", name), zap.Error(err))
			return err
		}
	}
	m.logger.Info("index templates configured", zap.Int("count", len(templates)))
	return nil
}

// ApplyISMPolicy loads and upserts all per-type ISM lifecycle policies.
// Each index type (alerts, events, fim, system, vulnerability, audit) gets
// its own policy with appropriate retention and rollover settings.
func (m *Manager) ApplyISMPolicy() error {
	policies := []struct {
		file     string
		policyID string
	}{
		{"lifecycle/alerts_policy.json", "watchvault-alerts-policy"},
		{"lifecycle/events_policy.json", "watchvault-events-policy"},
		{"lifecycle/fim_policy.json", "watchvault-fim-policy"},
		{"lifecycle/system_policy.json", "watchvault-system-policy"},
		{"lifecycle/vulnerability_policy.json", "watchvault-vulnerability-policy"},
		{"lifecycle/audit_policy.json", "watchvault-audit-policy"},
	}

	prefix := m.cfg.Prefix
	if prefix == "" {
		prefix = "watchvault"
	}

	for _, p := range policies {
		data, err := lifecycleFS.ReadFile(p.file)
		if err != nil {
			m.logger.Warn("lifecycle policy file not found", zap.String("file", p.file))
			continue
		}

		policyID := p.policyID
		if prefix != "watchvault" {
			data = []byte(strings.ReplaceAll(string(data), "watchvault", prefix))
			policyID = strings.ReplaceAll(p.policyID, "watchvault", prefix)
		}

		var policy map[string]interface{}
		if err := json.Unmarshal(data, &policy); err != nil {
			m.logger.Warn("invalid policy json", zap.String("file", p.file), zap.Error(err))
			continue
		}

		if err := m.client.PutISMPolicy(policyID, policy); err != nil {
			m.logger.Warn("failed to apply ISM policy", zap.String("policy_id", policyID), zap.Error(err))
		} else {
			m.logger.Info("ISM policy applied", zap.String("policy_id", policyID))
		}
	}
	return nil
}

// StartRetentionScheduler runs a daily job that deletes watchvault-* indices
// older than cfg.RetentionDays. This is the ILM fallback for OpenSearch
// distributions that don't support the ISM plugin.
func (m *Manager) StartRetentionScheduler(ctx context.Context) {
	if m.cfg.RetentionDays <= 0 {
		m.logger.Info("index retention disabled (retention_days=0)")
		return
	}
	go func() {
		// Run once at startup, then daily.
		m.runRetention()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.runRetention()
			}
		}
	}()
	m.logger.Info("index retention scheduler started",
		zap.Int("retention_days", m.cfg.RetentionDays))
}

func (m *Manager) runRetention() {
	prefix := m.cfg.Prefix
	if prefix == "" {
		prefix = "watchvault"
	}
	cutoff := time.Now().AddDate(0, 0, -m.cfg.RetentionDays)

	indices, err := m.client.ListIndices(prefix + "-*")
	if err != nil {
		m.logger.Warn("retention: failed to list indices", zap.Error(err))
		return
	}

	for _, idx := range indices {
		name, _ := idx["index"].(string)
		if name == "" {
			continue
		}
		// Index names end with -YYYY.MM.DD
		date, err := parseDateSuffix(name)
		if err != nil {
			continue // skip indices without a date suffix
		}
		if date.Before(cutoff) {
			if err := m.client.DeleteIndex(name); err != nil {
				m.logger.Warn("retention: failed to delete index",
					zap.String("index", name), zap.Error(err))
			} else {
				m.logger.Info("retention: deleted old index",
					zap.String("index", name),
					zap.String("age", fmt.Sprintf("%.0f days", time.Since(date).Hours()/24)))
			}
		}
	}
}

// parseDateSuffix extracts the date from an index name ending in -YYYY.MM.DD.
func parseDateSuffix(name string) (time.Time, error) {
	parts := strings.Split(name, "-")
	if len(parts) == 0 {
		return time.Time{}, fmt.Errorf("no suffix")
	}
	suffix := parts[len(parts)-1]
	return time.Parse("2006.01.02", suffix)
}

