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
		cf := &compiledField{
			equals:   fm.Equals,
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
