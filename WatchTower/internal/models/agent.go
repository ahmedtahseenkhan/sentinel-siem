package models

type Agent struct {
	ID            string            `json:"id" db:"id"`
	Hostname      string            `json:"hostname" db:"hostname"`
	OS            string            `json:"os" db:"os"`
	Platform      string            `json:"platform" db:"platform"`
	Version       string            `json:"version" db:"version"`
	GroupID       string            `json:"group_id,omitempty" db:"group_id"`
	Labels        map[string]string `json:"labels,omitempty"`
	Status        AgentStatus       `json:"status" db:"status"`
	IPAddress     string            `json:"ip_address,omitempty" db:"ip_address"`
	LastHeartbeat int64             `json:"last_heartbeat" db:"last_heartbeat"`
	RegisteredAt  int64             `json:"registered_at" db:"registered_at"`
}

type AgentStatus string

const (
	AgentStatusPending      AgentStatus = "pending"
	AgentStatusActive       AgentStatus = "active"
	AgentStatusDisconnected AgentStatus = "disconnected"
	AgentStatusStreaming     AgentStatus = "streaming"
)

type AgentGroup struct {
	ID              string `json:"id" db:"id"`
	Name            string `json:"name" db:"name"`
	Description     string `json:"description,omitempty" db:"description"`
	ConfigOverrides string `json:"config_overrides,omitempty" db:"config_overrides"`
}
