package models

type CaseStatus string
type CasePriority string

const (
	CaseStatusOpen          CaseStatus = "open"
	CaseStatusInvestigating CaseStatus = "investigating"
	CaseStatusResolved      CaseStatus = "resolved"
	CaseStatusClosed        CaseStatus = "closed"
	CaseStatusFalsePositive CaseStatus = "false_positive"
)

const (
	CasePriorityCritical CasePriority = "critical"
	CasePriorityHigh     CasePriority = "high"
	CasePriorityMedium   CasePriority = "medium"
	CasePriorityLow      CasePriority = "low"
)

type Case struct {
	ID          int64        `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Status      CaseStatus   `json:"status"`
	Priority    CasePriority `json:"priority"`
	Severity    int          `json:"severity"`
	Assignee    string       `json:"assignee,omitempty"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   int64        `json:"created_at"`
	UpdatedAt   int64        `json:"updated_at"`
	ClosedAt    int64        `json:"closed_at,omitempty"`
	Tags        []string     `json:"tags"`
	AlertIDs    []int64      `json:"alert_ids"`
	AgentIDs    []string     `json:"agent_ids"`
	NoteCount   int          `json:"note_count,omitempty"`

	// Ticketing fields (migration 009). GroupKey ties auto-created cases to a
	// (rule + agent) so repeat alerts append rather than spawn new cases.
	// DueAt is an SLA deadline in epoch millis (0 = no SLA). SLABreached and
	// Escalated are set by the SLA sweeper when DueAt passes.
	GroupKey    string `json:"group_key,omitempty"`
	DueAt       int64  `json:"due_at,omitempty"`
	SLABreached bool   `json:"sla_breached"`
	Escalated   bool   `json:"escalated"`
}

type CaseNote struct {
	ID        int64  `json:"id"`
	CaseID    int64  `json:"case_id"`
	Author    string `json:"author"`
	Content   string `json:"content"`
	CreatedAt int64  `json:"created_at"`
}

type CaseEvidence struct {
	ID      int64  `json:"id"`
	CaseID  int64  `json:"case_id"`
	Title   string `json:"title"`
	Type    string `json:"type"` // log, alert, screenshot, note
	Content string `json:"content"`
	AddedBy string `json:"added_by"`
	AddedAt int64  `json:"added_at"`
}

// CaseHistory is one entry in a case's state-change audit trail. Actions:
// created, status_changed, assignee_changed, priority_changed, sla_breached.
type CaseHistory struct {
	ID        int64  `json:"id"`
	CaseID    int64  `json:"case_id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Field     string `json:"field,omitempty"`
	OldValue  string `json:"old_value,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
	CreatedAt int64  `json:"created_at"`
}
