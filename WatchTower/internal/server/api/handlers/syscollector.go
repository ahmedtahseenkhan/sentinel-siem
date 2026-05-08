package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/store"
)

// SyscollectorHandler handles asset inventory queries.
type SyscollectorHandler struct {
	store *store.Store
}

// NewSyscollectorHandler creates a syscollector handler.
func NewSyscollectorHandler(s *store.Store) *SyscollectorHandler {
	return &SyscollectorHandler{store: s}
}

// Hardware returns hardware inventory for an agent.
func (h *SyscollectorHandler) Hardware(w http.ResponseWriter, r *http.Request) {
	h.getByType(w, r, "syscollector.hardware")
}

// OS returns OS information for an agent.
func (h *SyscollectorHandler) OS(w http.ResponseWriter, r *http.Request) {
	h.getByType(w, r, "syscollector.os")
}

// Packages returns installed packages for an agent.
func (h *SyscollectorHandler) Packages(w http.ResponseWriter, r *http.Request) {
	h.getByType(w, r, "syscollector.packages")
}

// Ports returns listening ports for an agent.
func (h *SyscollectorHandler) Ports(w http.ResponseWriter, r *http.Request) {
	h.getByType(w, r, "syscollector.ports")
}

// NetInterfaces returns network interfaces for an agent.
func (h *SyscollectorHandler) NetInterfaces(w http.ResponseWriter, r *http.Request) {
	h.getByType(w, r, "syscollector.netif")
}

func (h *SyscollectorHandler) getByType(w http.ResponseWriter, r *http.Request, eventType string) {
	agentID := chi.URLParam(r, "agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	alerts, err := h.store.ListAlertsByType(agentID, eventType, 500, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Extract fields from event data
	var items []map[string]interface{}
	for _, alert := range alerts {
		var eventData map[string]interface{}
		if err := json.Unmarshal([]byte(alert.EventData), &eventData); err != nil {
			continue
		}
		fields, _ := eventData["fields"].(map[string]interface{})
		if fields != nil {
			fields["timestamp"] = alert.Timestamp
			items = append(items, fields)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":    agentID,
		"type":        eventType,
		"total_items": len(items),
		"items":       items,
	})
}
