package models

// PlaybookTrigger defines the conditions under which a playbook auto-fires.
type PlaybookTrigger struct {
	MinLevel   int      `json:"min_level"`   // alert level threshold (1-15)
	RuleIDs    []int    `json:"rule_ids"`    // empty = any rule
	RuleGroups []string `json:"rule_groups"` // e.g. ["authentication", "fim"]
	AgentIDs   []string `json:"agent_ids"`   // empty = any agent
}

// PlaybookAction is one step in a playbook.
type PlaybookAction struct {
	Type              string            `json:"type"`               // block_ip, kill_process, isolate_host, disable_account, restart_service, create_case, create_ticket, notify_slack, notify_email, webhook, add_to_watchlist, quarantine_file, force_logoff
	Params            map[string]string `json:"params"`             // action-specific; supports {{template}} vars
	TimeoutSeconds    int               `json:"timeout_seconds"`    // 0 = 30s default
	ContinueOnFailure bool              `json:"continue_on_failure"`
}

// Playbook is a named, reusable response workflow.
type Playbook struct {
	ID          int64            `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Enabled     bool             `json:"enabled"`
	DryRun      bool             `json:"dry_run"`      // log actions but skip execution
	Trigger     PlaybookTrigger  `json:"trigger"`
	Actions     []PlaybookAction `json:"actions"`
	CreatedAt   int64            `json:"created_at"`
	UpdatedAt   int64            `json:"updated_at"`
	RunCount    int64            `json:"run_count"`
}

// PlaybookExecution is one run of a playbook triggered by an alert.
type PlaybookExecution struct {
	ID          int64                    `json:"id"`
	PlaybookID  int64                    `json:"playbook_id"`
	AlertID     int64                    `json:"alert_id"`
	AgentID     string                   `json:"agent_id"`
	Status      string                   `json:"status"` // running, success, failed, partial
	StartedAt   int64                    `json:"started_at"`
	CompletedAt int64                    `json:"completed_at"`
	Results     []PlaybookActionResult   `json:"results"`
}

// PlaybookActionResult captures the outcome of one action step.
type PlaybookActionResult struct {
	ActionType string `json:"action_type"`
	Status     string `json:"status"` // success, failed, skipped
	Message    string `json:"message,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}
