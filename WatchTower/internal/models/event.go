package models

type Event struct {
	ID        string                 `json:"id"`
	Timestamp int64                  `json:"timestamp"`
	Type      string                 `json:"type"`
	AgentID   string                 `json:"agent_id"`
	AgentName string                 `json:"agent_name,omitempty"`
	Fields    map[string]interface{} `json:"fields"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Decoded   map[string]string      `json:"decoded,omitempty"`
}
