package models

type ActiveResponse struct {
	ID         string `json:"id" db:"id"`
	AgentID    string `json:"agent_id" db:"agent_id"`
	Action     string `json:"action" db:"action"`
	Parameters string `json:"parameters,omitempty" db:"parameters"`
	Status     string `json:"status" db:"status"`
	CreatedAt  int64  `json:"created_at" db:"created_at"`
	ExecutedAt int64  `json:"executed_at,omitempty" db:"executed_at"`
	Result     string `json:"result,omitempty" db:"result"`
}

type CommandStatus string

const (
	CommandPending  CommandStatus = "pending"
	CommandSent     CommandStatus = "sent"
	CommandExecuted CommandStatus = "executed"
	CommandFailed   CommandStatus = "failed"
)
