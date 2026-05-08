package sca

import (
	"os"
	"path/filepath"

	"github.com/watchnode/watchnode/internal/agent"
	"gopkg.in/yaml.v3"
)

// PolicyFile is the YAML structure for a policy file.
type PolicyFile struct {
	Policy agent.SCAPolicy `yaml:"policy"`
}

// LoadPolicies loads all .yaml policy files from the given directories.
func LoadPolicies(dirs []string) ([]agent.SCAPolicy, error) {
	var policies []agent.SCAPolicy
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			continue
		}
		for _, f := range files {
			p, err := loadPolicyFile(f)
			if err != nil {
				continue
			}
			policies = append(policies, p)
		}
	}
	return policies, nil
}

func loadPolicyFile(path string) (agent.SCAPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return agent.SCAPolicy{}, err
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return agent.SCAPolicy{}, err
	}
	return pf.Policy, nil
}
