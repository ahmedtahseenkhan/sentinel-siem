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

func loadRulesFile(path string) ([]models.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf models.RulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}
	return rf.Rules, nil
}
