package models

type Alert struct {
	ID          int64          `json:"id" db:"id"`
	RuleID      int            `json:"rule_id" db:"rule_id"`
	Level       int            `json:"level" db:"level"`
	AgentID     string         `json:"agent_id" db:"agent_id"`
	Timestamp   int64          `json:"timestamp" db:"timestamp"`
	Title       string         `json:"title" db:"title"`
	Description string         `json:"description" db:"description"`
	EventData   string         `json:"event_data" db:"event_data"`
	RuleGroups  []string       `json:"rule_groups,omitempty"`
	MitreAttack []MitreMapping `json:"mitre,omitempty"`
	Forwarded   bool           `json:"forwarded" db:"forwarded"`
}
