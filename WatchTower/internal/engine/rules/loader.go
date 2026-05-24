package rules

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func loadRulesFromDir(dir string, logger *zap.Logger) ([]*compiledRule, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var compiled []*compiledRule
	for _, f := range files {
		rules, err := loadRulesFile(f)
		if err != nil {
			logger.Warn("failed to load rules file", zap.String("file", f), zap.Error(err))
			continue
		}
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			cr, err := compileRule(r)
			if err != nil {
				logger.Warn("failed to compile rule", zap.Int("id", r.ID), zap.Error(err))
				continue
			}
			compiled = append(compiled, cr)
		}
		logger.Debug("rules loaded", zap.String("file", f), zap.Int("count", len(rules)))
	}
	return compiled, nil
}

// loadRulesFile accepts two YAML shapes:
//
//	rules:                 # wrapped form (older batches: 0050-6300)
//	  - id: 11001
//	    ...
//
// or
//
//	- id: 19100            # bare-list form (newer batches: 7100-9100)
//	  ...
//
// Both shapes round-trip through []models.Rule the same way; without this
// fallback ~800 rules I wrote in batches 7100-9100 (compliance, APT
// actors, eCrime, mobile, OT/ICS, edge, email-deep, DLP/browser, IGA,
// data warehouse + AI) were silently ignored because they were written as
// bare top-level arrays. Surfaced by per_role_test.go.
func loadRulesFile(path string) ([]models.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Try wrapped form first (cheap, validates the historical shape).
	var rf models.RulesFile
	if err := yaml.Unmarshal(data, &rf); err == nil && len(rf.Rules) > 0 {
		return rf.Rules, nil
	}
	// Fall back to bare top-level array.
	var bare []models.Rule
	if err := yaml.Unmarshal(data, &bare); err == nil && len(bare) > 0 {
		return bare, nil
	}
	// If both succeed-but-empty (file with only comments), return empty no-err.
	// If the first unmarshal errored AND the bare also errored, propagate the
	// bare error so the operator sees a real diagnostic.
	if err := yaml.Unmarshal(data, &bare); err != nil {
		return nil, err
	}
	return nil, nil
}
