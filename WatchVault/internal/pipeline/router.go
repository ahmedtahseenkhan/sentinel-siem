package pipeline

import "strings"

type Router struct {
	prefix string
}

func NewRouter(prefix string) *Router {
	if prefix == "" {
		prefix = "watchvault"
	}
	return &Router{prefix: prefix}
}

func (r *Router) Route(eventType string) string {
	parts := strings.SplitN(eventType, ".", 2)
	if len(parts) == 0 {
		return "events"
	}

	switch parts[0] {
	case "fim":
		return "fim"
	case "system":
		return "system"
	case "process":
		return "events"
	case "network":
		return "events"
	case "vulnerability":
		return "vulnerability"
	case "log":
		return "events"
	case "audit":
		return "audit"
	default:
		return "events"
	}
}
