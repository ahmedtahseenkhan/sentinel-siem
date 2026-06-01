package models

type Rule struct {
	ID             int                `yaml:"id" json:"id"`
	Level          int                `yaml:"level" json:"level"`
	Description    string             `yaml:"description" json:"description"`
	Groups         []string           `yaml:"groups" json:"groups"`
	Match          RuleMatch          `yaml:"match" json:"match"`
	CDBLookup      *CDBLookup         `yaml:"cdb_lookup,omitempty" json:"cdb_lookup,omitempty"`
	Threshold      *RuleThreshold     `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	Correlation    *RuleCorrelation   `yaml:"correlation,omitempty" json:"correlation,omitempty"`
	Alert          RuleAlert          `yaml:"alert" json:"alert"`
	ActiveResponse *ActiveResponseRef `yaml:"active_response,omitempty" json:"active_response,omitempty"`
	MitreAttack    []MitreMapping     `yaml:"mitre,omitempty" json:"mitre,omitempty"`
	Enabled        bool               `yaml:"enabled" json:"enabled"`
}

type RuleMatch struct {
	Type   string                `yaml:"type" json:"type"`
	Fields map[string]FieldMatch `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// FieldMatch describes how to match one event field against a constraint.
// Two equivalent spellings are accepted for exact-match because earlier
// rule batches were written before the canonical "equals" key was settled:
//
//	field: {equals: 4624}      # canonical
//	field: {value: 4624}       # legacy (batches 2300-2700, 1000-1900)
//
// The rule compiler normalises both into the same string comparison. If
// both keys are set, Equals wins.
type FieldMatch struct {
	Regex    string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Equals   string `yaml:"equals,omitempty" json:"equals,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	Contains string `yaml:"contains,omitempty" json:"contains,omitempty"`
}

type CDBLookup struct {
	List  string `yaml:"list" json:"list"`
	Field string `yaml:"field" json:"field"`
}

type RuleAlert struct {
	Title string `yaml:"title" json:"title"`
}

type ActiveResponseRef struct {
	Action string `yaml:"action" json:"action"`
	Field  string `yaml:"field" json:"field"`
}

type Decoder struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Match       DecoderMatch     `yaml:"match" json:"match"`
	Extract     []DecoderExtract `yaml:"extract" json:"extract"`
}

type DecoderMatch struct {
	Type string            `yaml:"type" json:"type"`
	Tags map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

type DecoderExtract struct {
	Field string `yaml:"field" json:"field"`
	Regex string `yaml:"regex" json:"regex"`
}

type RulesFile struct {
	Rules []Rule `yaml:"rules"`
}

type DecodersFile struct {
	Decoders []Decoder `yaml:"decoders"`
}

// MitreMapping maps a rule to MITRE ATT&CK framework.
type MitreMapping struct {
	TacticID      string `yaml:"tactic_id" json:"tactic_id"`
	TacticName    string `yaml:"tactic_name" json:"tactic_name"`
	TechniqueID   string `yaml:"technique_id" json:"technique_id"`
	TechniqueName string `yaml:"technique_name" json:"technique_name"`
}

// RuleThreshold enables frequency-based correlation.
// An alert is only generated when the rule matches at least Count times
// within PeriodSecs seconds, optionally grouped by a field value.
//
// Example YAML:
//
//	threshold:
//	  count: 5
//	  period_secs: 60
//	  group_by: "srcip"     # optional; omit to group all agents together
type RuleThreshold struct {
	Count      int    `yaml:"count" json:"count"`
	PeriodSecs int    `yaml:"period_secs" json:"period_secs"`
	GroupBy    string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
}

// RuleCorrelation is the Wazuh-style spelling of a frequency rule used across
// the rule corpus: an alert fires only when the rule matches at least
// Threshold times within Window (a Go duration string like "5m"/"1h"),
// optionally grouped by one or more fields.
//
//	correlation:
//	  window: "5m"
//	  threshold: 5
//	  group_by: ["src_ip"]      # one or more fields; values are concatenated
//
// Equivalent to RuleThreshold; the engine honours whichever block is present.
type RuleCorrelation struct {
	Window    string   `yaml:"window" json:"window"`
	Threshold int      `yaml:"threshold" json:"threshold"`
	GroupBy   []string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
}
