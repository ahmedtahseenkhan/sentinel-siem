package index

import (
	"embed"
	"encoding/json"
	"fmt"
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

// ApplyISMPolicy loads the bundled default ISM lifecycle policy from
// lifecycle/default_policy.json and upserts it into OpenSearch.
// If the configured index prefix differs from "watchvault", the policy ID is
// adjusted accordingly so that ISM index patterns still match.
func (m *Manager) ApplyISMPolicy() error {
	data, err := lifecycleFS.ReadFile("lifecycle/default_policy.json")
	if err != nil {
		return err
	}

	// Rewrite prefix references if a custom prefix is configured.
	if m.cfg.Prefix != "" && m.cfg.Prefix != "watchvault" {
		replaced := strings.ReplaceAll(string(data), "watchvault", m.cfg.Prefix)
		data = []byte(replaced)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(data, &policy); err != nil {
		return err
	}

	// Inject configured retention days into the delete transition when set.
	if m.cfg.RetentionDays > 0 {
		injectRetention(policy, m.cfg.RetentionDays)
	}

	policyID := "watchvault-default"
	if m.cfg.Prefix != "" && m.cfg.Prefix != "watchvault" {
		policyID = m.cfg.Prefix + "-default"
	}

	return m.client.PutISMPolicy(policyID, policy)
}

// injectRetention overwrites the delete-state transition age with the given
// number of days so operators can tune retention via config rather than
// editing the embedded JSON.
func injectRetention(policy map[string]interface{}, days int) {
	p, ok := policy["policy"].(map[string]interface{})
	if !ok {
		return
	}
	states, ok := p["states"].([]interface{})
	if !ok {
		return
	}
	age := fmt.Sprintf("%dd", days)
	for _, s := range states {
		state, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		if state["name"] == "warm" {
			transitions, ok := state["transitions"].([]interface{})
			if !ok {
				continue
			}
			for _, t := range transitions {
				tr, ok := t.(map[string]interface{})
				if !ok {
					continue
				}
				if tr["state_name"] == "delete" {
					if cond, ok := tr["conditions"].(map[string]interface{}); ok {
						cond["min_index_age"] = age
					}
				}
			}
		}
	}
}
