package rules

import (
	"regexp"

	"github.com/watchtower/watchtower/internal/models"
)

type compiledRule struct {
	def    models.Rule
	fields map[string]*compiledField
}

type compiledField struct {
	regex    *regexp.Regexp
	equals   string
	contains string
}

func compileRule(r models.Rule) (*compiledRule, error) {
	cr := &compiledRule{
		def:    r,
		fields: make(map[string]*compiledField),
	}
	for name, fm := range r.Match.Fields {
		// Normalise legacy `value:` into `equals:`. Without this fallback the
		// older rule batches (2300, 1000-1900) loaded but their value-based
		// field filters were silently ignored — every rule matched every
		// event of the right type. Surfaced by per_role_test.go.
		eq := fm.Equals
		if eq == "" {
			eq = fm.Value
		}
		cf := &compiledField{
			equals:   eq,
			contains: fm.Contains,
		}
		if fm.Regex != "" {
			re, err := regexp.Compile(fm.Regex)
			if err != nil {
				return nil, err
			}
			cf.regex = re
		}
		cr.fields[name] = cf
	}
	return cr, nil
}
