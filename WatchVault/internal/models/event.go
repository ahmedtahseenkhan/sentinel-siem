package models

type IndexEvent struct {
	ID        string                 `json:"id"`
	Timestamp int64                  `json:"timestamp"`
	EventType string                 `json:"event_type"`
	AgentID   string                 `json:"agent_id"`
	AgentName string                 `json:"agent_name,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Tags      map[string]string      `json:"tags,omitempty"`
}

type IndexAlert struct {
	ID              string                 `json:"id"`
	Timestamp       int64                  `json:"timestamp"`
	RuleID          int                    `json:"rule_id"`
	RuleLevel       int                    `json:"rule_level"`
	RuleDescription string                 `json:"rule_description"`
	RuleGroups      []string               `json:"rule_groups"`
	AgentID         string                 `json:"agent_id"`
	AgentName       string                 `json:"agent_name"`
	Title           string                 `json:"title"`
	EventData       map[string]interface{} `json:"event_data"`
}
