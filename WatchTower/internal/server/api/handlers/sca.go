package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/store"
)

// SCAHandler handles SCA result queries.
type SCAHandler struct {
	store *store.Store
}

// NewSCAHandler creates an SCA handler.
func NewSCAHandler(s *store.Store) *SCAHandler {
	return &SCAHandler{store: s}
}

// GetByAgent returns SCA results for a specific agent queried from stored alerts.
func (h *SCAHandler) GetByAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	// Query SCA-related alerts from the store
	alerts, err := h.store.ListAlertsByType(agentID, "sca", 100, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":    agentID,
		"total_items": len(alerts),
		"items":       alerts,
	})
}

// ListPolicies returns SCA policy summaries for an agent.
func (h *SCAHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	alerts, err := h.store.ListAlertsByType(agentID, "sca", 1000, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Group by policy_id from event data
	policies := map[string]map[string]interface{}{}
	for _, alert := range alerts {
		var eventData map[string]interface{}
		if err := json.Unmarshal([]byte(alert.EventData), &eventData); err != nil {
			continue
		}
		fields, _ := eventData["fields"].(map[string]interface{})
		if fields == nil {
			continue
		}
		policyID, _ := fields["policy_id"].(string)
		if policyID == "" {
			continue
		}
		if _, exists := policies[policyID]; !exists {
			policies[policyID] = map[string]interface{}{
				"policy_id": policyID,
				"name":      fields["policy_name"],
				"total":     fields["total"],
				"passed":    fields["passed"],
				"failed":    fields["failed"],
				"score":     fields["score"],
			}
		}
	}

	policyList := make([]map[string]interface{}, 0, len(policies))
	for _, p := range policies {
		policyList = append(policyList, p)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":    agentID,
		"total_items": len(policyList),
		"items":       policyList,
	})
}
