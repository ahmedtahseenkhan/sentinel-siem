package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/pkg/proto"
)

type AgentHandler struct {
	registry *registry.Registry
}

func NewAgentHandler(reg *registry.Registry) *AgentHandler {
	return &AgentHandler{registry: reg}
}

func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 100
	}

	agents, err := h.registry.ListAgents(status, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  agents,
		"total": len(agents),
	})
}

func (h *AgentHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	agent, err := h.registry.GetAgent(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": agent})
}

func (h *AgentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.registry.DeleteAgent(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "agent deleted"})
}

func (h *AgentHandler) AssignGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		GroupID string `json:"group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.registry.UpdateAgentGroup(id, body.GroupID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "group assigned"})
}

// PushConfig pushes a partial config update to a specific agent in real time.
// The JSON request body is forwarded as a config_update ManagerCommand payload.
// Any field not included in the body is left unchanged on the agent.
//
// Example request body:
//
//	{
//	  "active_response": {
//	    "enabled": true,
//	    "allowed_commands": ["kill-process", "firewall-drop"]
//	  }
//	}
func (h *AgentHandler) PushConfig(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "missing agent_id")
		return
	}

	// Read and size-cap the body to prevent oversized payloads.
	const maxConfigPayload = 64 * 1024 // 64 KiB
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigPayload)

	var payload json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	cmd := &proto.ManagerCommand{
		CommandType: "config_update",
		Payload:     []byte(payload),
	}

	delivered, queued := h.registry.SendCommandStatus(agentID, cmd)
	if delivered {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "delivered",
			"message":  "config_update delivered to online agent",
			"agent_id": agentID,
		})
		return
	}
	if queued {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"status":   "queued",
			"message":  "agent offline — config_update queued for delivery on next reconnect",
			"agent_id": agentID,
			"pending":  h.registry.PendingCommandCount(agentID),
		})
		return
	}
	writeError(w, http.StatusServiceUnavailable, "agent not connected and queue full")
}

// PushConfigBulk pushes a config update to every agent matching the optional
// filters. Without filters, applies to ALL agents. Filters supported:
//   - status: "running" / "disconnected" / etc
//   - os:     "windows" / "linux"
//   - label:  "team=security" (repeatable via comma)
//
// Online agents receive the update immediately; offline agents have it
// queued and delivered on their next reconnect.
//
// Example: POST /api/v1/agents/config?os=windows
//
//	{ "performance": { "max_cpu_percent": 25 } }
func (h *AgentHandler) PushConfigBulk(w http.ResponseWriter, r *http.Request) {
	const maxConfigPayload = 64 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigPayload)
	var payload json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	statusFilter := r.URL.Query().Get("status")
	osFilter := r.URL.Query().Get("os")
	labelFilter := r.URL.Query().Get("label")

	agents, err := h.registry.ListAgents(statusFilter, 10000, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var delivered, queued, skipped int
	targetIDs := make([]string, 0, len(agents))

	for _, a := range agents {
		if osFilter != "" && a.OS != osFilter {
			skipped++
			continue
		}
		if labelFilter != "" {
			parts := splitKV(labelFilter)
			if a.Labels == nil || a.Labels[parts[0]] != parts[1] {
				skipped++
				continue
			}
		}
		cmd := &proto.ManagerCommand{
			CommandType: "config_update",
			Payload:     []byte(payload),
		}
		d, q := h.registry.SendCommandStatus(a.ID, cmd)
		if d {
			delivered++
		} else if q {
			queued++
		}
		targetIDs = append(targetIDs, a.ID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":        "bulk config_update dispatched",
		"total_targeted": len(targetIDs),
		"delivered":      delivered,
		"queued":         queued,
		"skipped":        skipped,
		"filters": map[string]string{
			"status": statusFilter,
			"os":     osFilter,
			"label":  labelFilter,
		},
	})
}

func splitKV(s string) [2]string {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}
