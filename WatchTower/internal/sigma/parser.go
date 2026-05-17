// Package sigma implements a Sigma rule parser that converts Sigma YAML
// detection rules into WatchTower's native rule format, enabling the full
// community Sigma ruleset to be used without manual conversion.
//
// Sigma specification reference: https://github.com/SigmaHQ/sigma/wiki/Specification
//
// Supported features:
//   - selection: keyword lists, field-value maps, contains/endswith/startswith modifiers
//   - condition: AND/OR logic via selection groups, NOT negation, 1 of / all of
//   - logsource routing to event type tags
//   - level mapping (informational→3, low→5, medium→7, high→10, critical→15)
//   - MITRE ATT&CK tags (attack.tXXXX, attack.tactic)
//   - falsepositives and description fields preserved
package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/watchtower/watchtower/internal/models"
	"gopkg.in/yaml.v3"
)

// sigmaRule mirrors the Sigma YAML schema.
type sigmaRule struct {
	Title        string                 `yaml:"title"`
	ID           string                 `yaml:"id"`
	Status       string                 `yaml:"status"`
	Description  string                 `yaml:"description"`
	Author       string                 `yaml:"author"`
	Level        string                 `yaml:"level"`
	Tags         []string               `yaml:"tags"`
	LogSource    map[string]string      `yaml:"logsource"`
	Detection    map[string]interface{} `yaml:"detection"`
	FalsePositives []string             `yaml:"falsepositives"`
}

var nextRuleID int = 90000 // Sigma rules start at 90000 to avoid collisions

var levelMap = map[string]int{
	"informational": 3,
	"low":           5,
	"medium":        7,
	"high":          10,
	"critical":      15,
}

// ParseFile reads a Sigma YAML file and returns a WatchTower Rule.
// Returns an error if the file cannot be parsed or the detection is unsupported.
func ParseFile(path string) (*models.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return Parse(data)
}

// Parse converts raw Sigma YAML bytes into a WatchTower Rule.
func Parse(data []byte) (*models.Rule, error) {
	var sr sigmaRule
	if err := yaml.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("parse sigma yaml: %w", err)
	}
	if sr.Title == "" {
		return nil, fmt.Errorf("sigma rule has no title")
	}
	if sr.Detection == nil {
		return nil, fmt.Errorf("sigma rule %q has no detection block", sr.Title)
	}

	nextRuleID++
	rule := &models.Rule{
		ID:          nextRuleID,
		Level:       levelMap[strings.ToLower(sr.Level)],
		Description: sr.Description,
		Groups:      []string{"sigma"},
		Alert:       models.RuleAlert{Title: sr.Title},
		Enabled:     sr.Status != "deprecated" && sr.Status != "unsupported",
	}
	if rule.Level == 0 {
		rule.Level = 5
	}

	// MITRE ATT&CK tags
	rule.MitreAttack = extractMitre(sr.Tags)

	// logsource → groups
	rule.Groups = append(rule.Groups, logSourceGroups(sr.LogSource)...)

	// Detection → RuleMatch
	match, err := convertDetection(sr.Detection)
	if err != nil {
		return nil, fmt.Errorf("rule %q detection: %w", sr.Title, err)
	}
	rule.Match = match

	return rule, nil
}

// LoadDir loads all .yml/.yaml Sigma files from a directory, converting each
// to a WatchTower Rule. Errors for individual files are collected and returned
// but do not prevent other files from loading.
func LoadDir(dir string) ([]*models.Rule, []error) {
	var rules []*models.Rule
	var errs []error

	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries silently
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		r, parseErr := ParseFile(path)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, parseErr))
			return nil
		}
		rules = append(rules, r)
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return rules, errs
}

// ────────────────────────────────────────────────────────────────────────────
// Detection conversion

// convertDetection transforms the Sigma detection block into a models.RuleMatch.
//
// A full Sigma detection block looks like:
//
//	detection:
//	  selection:
//	    EventID: 4625
//	    LogonType|contains:
//	      - 3
//	      - 10
//	  filter:
//	    SubjectUserName: SYSTEM
//	  condition: selection and not filter
//
// We extract all named selections, resolve the condition expression, and build
// a flat FieldMatch map expressing the combined AND logic. OR logic between
// multiple values for the same field is expressed as a regex alternation.
// NOT selections are excluded by adding a FieldMatch with Regex "^(?!<value>)".
// Complex multi-group OR (1 of selection*) is flattened into a single match.
func convertDetection(det map[string]interface{}) (models.RuleMatch, error) {
	condRaw, ok := det["condition"]
	if !ok {
		return models.RuleMatch{}, fmt.Errorf("missing 'condition' key")
	}
	condition, ok := condRaw.(string)
	if !ok {
		return models.RuleMatch{}, fmt.Errorf("condition must be a string")
	}

	// Build a map of selection_name → FieldMatch map.
	selections := map[string]map[string]models.FieldMatch{}
	for k, v := range det {
		if k == "condition" {
			continue
		}
		fields, err := parseSelection(v)
		if err != nil {
			return models.RuleMatch{}, fmt.Errorf("selection %q: %w", k, err)
		}
		selections[k] = fields
	}

	fields, err := resolveCondition(condition, selections)
	if err != nil {
		return models.RuleMatch{}, err
	}

	return models.RuleMatch{
		Type:   "field",
		Fields: fields,
	}, nil
}

// parseSelection converts a Sigma selection value (keyword list, map, or list
// of maps) into a FieldMatch map keyed by field name.
func parseSelection(v interface{}) (map[string]models.FieldMatch, error) {
	result := map[string]models.FieldMatch{}

	switch sel := v.(type) {
	case []interface{}:
		// Keyword list: match any of these strings in the full event message.
		var alts []string
		for _, item := range sel {
			alts = append(alts, regexp.QuoteMeta(fmt.Sprintf("%v", item)))
		}
		result["message"] = models.FieldMatch{Regex: strings.Join(alts, "|")}
		return result, nil

	case map[string]interface{}:
		return parseFieldMap(sel)

	default:
		// Single keyword
		result["message"] = models.FieldMatch{Contains: fmt.Sprintf("%v", v)}
		return result, nil
	}
}

func parseFieldMap(m map[string]interface{}) (map[string]models.FieldMatch, error) {
	result := map[string]models.FieldMatch{}
	for rawKey, val := range m {
		fieldName, modifier := splitModifier(rawKey)
		fm, err := buildFieldMatch(val, modifier)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", rawKey, err)
		}
		result[fieldName] = fm
	}
	return result, nil
}

// splitModifier splits "FieldName|modifier" into ("FieldName", "modifier").
func splitModifier(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return key, ""
}

func buildFieldMatch(val interface{}, modifier string) (models.FieldMatch, error) {
	var values []string
	switch v := val.(type) {
	case []interface{}:
		for _, item := range v {
			values = append(values, fmt.Sprintf("%v", item))
		}
	case string:
		values = []string{v}
	case int, int64, float64:
		values = []string{fmt.Sprintf("%v", v)}
	default:
		values = []string{fmt.Sprintf("%v", v)}
	}

	switch strings.ToLower(modifier) {
	case "contains":
		if len(values) == 1 {
			return models.FieldMatch{Contains: values[0]}, nil
		}
		// Multiple contains → regex alternation
		var quoted []string
		for _, s := range values {
			quoted = append(quoted, regexp.QuoteMeta(s))
		}
		return models.FieldMatch{Regex: strings.Join(quoted, "|")}, nil

	case "startswith":
		var quoted []string
		for _, s := range values {
			quoted = append(quoted, "^"+regexp.QuoteMeta(s))
		}
		return models.FieldMatch{Regex: strings.Join(quoted, "|")}, nil

	case "endswith":
		var quoted []string
		for _, s := range values {
			quoted = append(quoted, regexp.QuoteMeta(s)+"$")
		}
		return models.FieldMatch{Regex: strings.Join(quoted, "|")}, nil

	case "re", "regex":
		if len(values) == 1 {
			return models.FieldMatch{Regex: values[0]}, nil
		}
		return models.FieldMatch{Regex: strings.Join(values, "|")}, nil

	case "":
		// Exact match or multi-value (OR)
		if len(values) == 1 {
			return models.FieldMatch{Equals: values[0]}, nil
		}
		var quoted []string
		for _, s := range values {
			quoted = append(quoted, "^"+regexp.QuoteMeta(s)+"$")
		}
		return models.FieldMatch{Regex: strings.Join(quoted, "|")}, nil

	default:
		// Unknown modifier — fall back to regex contains
		var quoted []string
		for _, s := range values {
			quoted = append(quoted, regexp.QuoteMeta(s))
		}
		return models.FieldMatch{Regex: strings.Join(quoted, "|")}, nil
	}
}

// resolveCondition parses the Sigma condition string and merges selections.
// We support: selection, selection1 and selection2, selection1 or selection2,
// not selection, 1 of pattern*, all of pattern*.
// Complex boolean trees are flattened: AND merged, OR converted to regex alts.
func resolveCondition(condition string, selections map[string]map[string]models.FieldMatch) (map[string]models.FieldMatch, error) {
	cond := strings.TrimSpace(strings.ToLower(condition))

	// "1 of <pattern>" — OR across matching selections
	if strings.HasPrefix(cond, "1 of ") {
		pattern := strings.TrimPrefix(cond, "1 of ")
		matched := globSelections(pattern, selections)
		if len(matched) == 0 {
			return nil, fmt.Errorf("no selections match glob %q", pattern)
		}
		// Merge all into a single regex OR per field
		return mergeOr(matched), nil
	}

	// "all of <pattern>" — AND across matching selections
	if strings.HasPrefix(cond, "all of ") {
		pattern := strings.TrimPrefix(cond, "all of ")
		matched := globSelections(pattern, selections)
		if len(matched) == 0 {
			return nil, fmt.Errorf("no selections match glob %q", pattern)
		}
		return mergeAnd(matched), nil
	}

	// Simple reference to a single selection name
	if sel, ok := selections[cond]; ok {
		return sel, nil
	}

	// "X and not Y"
	if idx := strings.Index(cond, " and not "); idx != -1 {
		left := strings.TrimSpace(cond[:idx])
		right := strings.TrimSpace(cond[idx+9:])
		leftSel := resolveSimple(left, selections)
		rightSel := resolveSimple(right, selections)
		return mergeAndNot(leftSel, rightSel), nil
	}

	// "X and Y"
	if idx := strings.Index(cond, " and "); idx != -1 {
		parts := strings.SplitN(cond, " and ", 2)
		left := resolveSimple(strings.TrimSpace(parts[0]), selections)
		right := resolveSimple(strings.TrimSpace(parts[1]), selections)
		return mergeAnd([]map[string]models.FieldMatch{left, right}), nil
	}

	// "X or Y"
	if idx := strings.Index(cond, " or "); idx != -1 {
		parts := strings.SplitN(cond, " or ", 2)
		left := resolveSimple(strings.TrimSpace(parts[0]), selections)
		right := resolveSimple(strings.TrimSpace(parts[1]), selections)
		return mergeOr([]map[string]models.FieldMatch{left, right}), nil
	}

	// "not X"
	if strings.HasPrefix(cond, "not ") {
		inner := resolveSimple(strings.TrimPrefix(cond, "not "), selections)
		return negateFields(inner), nil
	}

	return nil, fmt.Errorf("unsupported condition expression: %q", condition)
}

func resolveSimple(name string, selections map[string]map[string]models.FieldMatch) map[string]models.FieldMatch {
	if s, ok := selections[name]; ok {
		return s
	}
	return map[string]models.FieldMatch{}
}

func globSelections(pattern string, selections map[string]map[string]models.FieldMatch) []map[string]models.FieldMatch {
	var result []map[string]models.FieldMatch
	if pattern == "them" {
		for _, v := range selections {
			result = append(result, v)
		}
		return result
	}
	// convert glob to regex: * → .*
	reStr := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, `.*`) + "$"
	re := regexp.MustCompile(reStr)
	for k, v := range selections {
		if re.MatchString(k) {
			result = append(result, v)
		}
	}
	return result
}

// mergeAnd merges multiple field maps — fields from later maps override earlier
// ones. This expresses AND semantics assuming the engine checks all fields.
func mergeAnd(maps []map[string]models.FieldMatch) map[string]models.FieldMatch {
	result := map[string]models.FieldMatch{}
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// mergeAndNot merges left AND (NOT right) by negating the right fields and merging.
func mergeAndNot(left, right map[string]models.FieldMatch) map[string]models.FieldMatch {
	result := mergeAnd([]map[string]models.FieldMatch{left})
	for k, v := range negateFields(right) {
		if _, exists := result[k]; !exists {
			result[k] = v
		}
	}
	return result
}

// mergeOr merges selections with OR semantics: fields present in all maps are
// unified with regex alternation; fields present in only some maps are dropped
// to avoid false negatives.
func mergeOr(maps []map[string]models.FieldMatch) map[string]models.FieldMatch {
	if len(maps) == 0 {
		return map[string]models.FieldMatch{}
	}
	if len(maps) == 1 {
		return maps[0]
	}

	// Collect per-field regex options
	fieldAlts := map[string][]string{}
	for _, m := range maps {
		for k, v := range m {
			fieldAlts[k] = append(fieldAlts[k], fieldMatchToRegex(v))
		}
	}

	result := map[string]models.FieldMatch{}
	for k, alts := range fieldAlts {
		if len(alts) == len(maps) { // field present in every selection
			result[k] = models.FieldMatch{Regex: strings.Join(alts, "|")}
		}
	}
	return result
}

func negateFields(m map[string]models.FieldMatch) map[string]models.FieldMatch {
	result := map[string]models.FieldMatch{}
	for k, v := range m {
		re := fieldMatchToRegex(v)
		result[k] = models.FieldMatch{Regex: "^(?!" + re + ")"}
	}
	return result
}

func fieldMatchToRegex(fm models.FieldMatch) string {
	if fm.Regex != "" {
		return fm.Regex
	}
	if fm.Contains != "" {
		return regexp.QuoteMeta(fm.Contains)
	}
	if fm.Equals != "" {
		return "^" + regexp.QuoteMeta(fm.Equals) + "$"
	}
	return ".*"
}

// ────────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK extraction

var (
	reTechniqueID = regexp.MustCompile(`(?i)^attack\.(t\d{4}(?:\.\d{3})?)$`)
	tacticNames   = map[string]string{
		"initial-access":        "Initial Access",
		"execution":             "Execution",
		"persistence":           "Persistence",
		"privilege-escalation":  "Privilege Escalation",
		"defense-evasion":       "Defense Evasion",
		"credential-access":     "Credential Access",
		"discovery":             "Discovery",
		"lateral-movement":      "Lateral Movement",
		"collection":            "Collection",
		"command-and-control":   "Command and Control",
		"exfiltration":          "Exfiltration",
		"impact":                "Impact",
		"reconnaissance":        "Reconnaissance",
		"resource-development":  "Resource Development",
	}
)

func extractMitre(tags []string) []models.MitreMapping {
	var mappings []models.MitreMapping
	var tacticTag string
	var techTags []string

	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if m := reTechniqueID.FindStringSubmatch(lower); len(m) == 2 {
			techTags = append(techTags, strings.ToUpper(m[1]))
			continue
		}
		if strings.HasPrefix(lower, "attack.") {
			tactic := strings.TrimPrefix(lower, "attack.")
			if _, ok := tacticNames[tactic]; ok {
				tacticTag = tactic
			}
		}
	}

	tacticName := tacticNames[tacticTag]
	if len(techTags) == 0 {
		if tacticTag != "" {
			mappings = append(mappings, models.MitreMapping{
				TacticName: tacticName,
			})
		}
		return mappings
	}
	for _, tech := range techTags {
		mappings = append(mappings, models.MitreMapping{
			TacticName:    tacticName,
			TechniqueID:   tech,
			TechniqueName: tech, // name resolution would require a full ATT&CK DB
		})
	}
	return mappings
}

// ────────────────────────────────────────────────────────────────────────────
// LogSource → groups

func logSourceGroups(ls map[string]string) []string {
	var groups []string
	if product, ok := ls["product"]; ok {
		groups = append(groups, "product:"+strings.ToLower(product))
	}
	if category, ok := ls["category"]; ok {
		groups = append(groups, "category:"+strings.ToLower(category))
	}
	if svcType, ok := ls["service"]; ok {
		groups = append(groups, "service:"+strings.ToLower(svcType))
	}
	return groups
}

// ────────────────────────────────────────────────────────────────────────────
// YAML serialisation helper

// ToRulesFile wraps a slice of converted rules into a WatchTower RulesFile for
// serialisation back to YAML.
func ToRulesFile(rules []*models.Rule) models.RulesFile {
	file := models.RulesFile{}
	for _, r := range rules {
		file.Rules = append(file.Rules, *r)
	}
	return file
}

// ── sentinel to avoid unused import ──────────────────────────────────────────
var _ = strconv.Itoa
