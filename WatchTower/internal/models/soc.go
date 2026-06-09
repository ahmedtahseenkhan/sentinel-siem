package models

// SOCEngineer is a member of the SOC who can be auto-assigned cases. It is the
// roster the assignment engine routes against; identity (LDAP) provides the
// display name/email for the same sam_account.
type SOCEngineer struct {
	SamAccount  string   `json:"sam_account"`
	SkillGroups []string `json:"skill_groups"`
	Tier        int      `json:"tier"`      // 1 junior .. 3 senior
	MaxLoad     int      `json:"max_load"`  // soft cap on concurrent open cases
	Active      bool     `json:"active"`
	CreatedAt   int64    `json:"created_at"`
	UpdatedAt   int64    `json:"updated_at"`

	// Computed at query time (not stored).
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	OpenLoad    int    `json:"open_load,omitempty"`
}

// SOCShift is one recurring coverage window for an engineer. Times are
// minutes-from-midnight UTC so on-shift checks need no timezone math. end_min
// may be less than start_min for an overnight window.
type SOCShift struct {
	ID         int64  `json:"id"`
	SamAccount string `json:"sam_account"`
	Weekday    int    `json:"weekday"`   // 0=Sun .. 6=Sat
	StartMin   int    `json:"start_min"` // minutes from 00:00 UTC
	EndMin     int    `json:"end_min"`   // minutes from 00:00 UTC
	OnCall     bool   `json:"on_call"`
}

// CaseMetrics is the manager-dashboard rollup over a time window.
type CaseMetrics struct {
	MTTRMin        int            `json:"mttr_min"`         // mean time to resolve, minutes
	OpenBySeverity map[string]int `json:"open_by_severity"` // priority -> open count
	OpenByAssignee map[string]int `json:"open_by_assignee"`
	SLABreachRate  float64        `json:"sla_breach_rate"`  // 0..1 over closed cases in window
	Resolved       int            `json:"resolved"`
	OpenTotal      int            `json:"open_total"`
}

// FPRuleStat is one noisy rule, ranked by how often its cases were closed as
// false positives.
type FPRuleStat struct {
	RuleID  int `json:"rule_id"`
	FPCount int `json:"fp_count"`
}
