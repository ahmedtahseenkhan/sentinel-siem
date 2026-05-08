package rules

import (
	"fmt"
	"strings"

	"github.com/watchtower/watchtower/internal/engine/cdb"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type Matcher struct {
	logger *zap.Logger
	rules  []*compiledRule
	cdb    *cdb.Manager

	// byType indexes rules by their match.type field for fast lookup.
	// Rules with an empty type (match any event) are stored under the "" key.
	byType map[string][]*compiledRule
}

func NewMatcher(logger *zap.Logger) *Matcher {
	return &Matcher{logger: logger, byType: make(map[string][]*compiledRule)}
}

func (m *Matcher) LoadFromDir(dir string) error {
	compiled, err := loadRulesFromDir(dir, m.logger)
	if err != nil {
		return err
	}
	m.rules = compiled
	m.rebuildIndex()
	return nil
}

// rebuildIndex (re)builds the byType map from the current rule list.
// Must be called after any change to m.rules.
func (m *Matcher) rebuildIndex() {
	idx := make(map[string][]*compiledRule, len(m.rules))
	for _, cr := range m.rules {
		key := cr.def.Match.Type // "" means "match any event type"
		idx[key] = append(idx[key], cr)
	}
	m.byType = idx
}

func (m *Matcher) SetCDB(c *cdb.Manager) {
	m.cdb = c
}

// Match returns all rules that fire for the given event.
// Rules are looked up via a type-keyed index for O(1) fan-out to the right
// candidate set, then evaluated. The wildcard bucket (type=="") is always
// included so rules without a type filter are never skipped.
func (m *Matcher) Match(event *models.Event) []*models.Rule {
	var matched []*models.Rule

	// Rules that match a specific event type.
	for _, cr := range m.byType[event.Type] {
		if m.matchRule(cr, event) {
			matched = append(matched, &cr.def)
		}
	}

	// Wildcard rules (no type constraint) — evaluated for every event.
	if event.Type != "" {
		for _, cr := range m.byType[""] {
			if m.matchRule(cr, event) {
				matched = append(matched, &cr.def)
			}
		}
	}

	return matched
}

func (m *Matcher) matchRule(cr *compiledRule, event *models.Event) bool {
	if cr.def.Match.Type != "" && cr.def.Match.Type != event.Type {
		return false
	}

	for fieldName, cf := range cr.fields {
		val := getFieldValue(event, fieldName)
		if !matchField(cf, val) {
			return false
		}
	}

	if cr.def.CDBLookup != nil && m.cdb != nil {
		fieldVal := getFieldValue(event, cr.def.CDBLookup.Field)
		if !m.cdb.Lookup(cr.def.CDBLookup.List, fieldVal) {
			return false
		}
	}

	return true
}

func matchField(cf *compiledField, val string) bool {
	if cf.equals != "" && val != cf.equals {
		return false
	}
	if cf.contains != "" && !strings.Contains(val, cf.contains) {
		return false
	}
	if cf.regex != nil && !cf.regex.MatchString(val) {
		return false
	}
	return true
}

func getFieldValue(event *models.Event, fieldName string) string {
	if v, ok := event.Decoded[fieldName]; ok {
		return v
	}
	if v, ok := event.Fields[fieldName]; ok {
		return fmt.Sprintf("%v", v)
	}
	if v, ok := event.Tags[fieldName]; ok {
		return v
	}
	return ""
}

func (m *Matcher) Add(rule models.Rule) error {
	cr, err := compileRule(rule)
	if err != nil {
		return err
	}
	m.rules = append(m.rules, cr)
	// Keep index in sync — add to the correct type bucket.
	key := cr.def.Match.Type
	m.byType[key] = append(m.byType[key], cr)
	return nil
}

func (m *Matcher) List() []models.Rule {
	var result []models.Rule
	for _, cr := range m.rules {
		result = append(result, cr.def)
	}
	return result
}

func (m *Matcher) Get(id int) *models.Rule {
	for _, cr := range m.rules {
		if cr.def.ID == id {
			return &cr.def
		}
	}
	return nil
}

func (m *Matcher) Count() int {
	return len(m.rules)
}
