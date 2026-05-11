package index

import (
	"embed"
	"encoding/json"
	"strings"

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

