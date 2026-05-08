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

	sent := h.registry.SendCommand(agentID, cmd)
	if !sent {
		writeError(w, http.StatusServiceUnavailable, "agent not connected")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "config_update dispatched",
		"agent_id": agentID,
	})
}
