package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/store"
)

type RbaHandler struct {
	store *store.Store
}

func NewRbaHandler(st *store.Store) *RbaHandler {
	return &RbaHandler{store: st}
}

// EntityRisk GET /api/v1/rba/entities
func (h *RbaHandler) ListEntities(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entities, err := h.store.ListRbaEntityRisk(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  entities,
		"total": len(entities),
	})
}

// GetEntity GET /api/v1/rba/entities/:id
func (h *RbaHandler) GetEntity(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	entity, _ := h.store.GetRbaEntityRisk(id)
	events, _ := h.store.ListRbaRiskEvents(id, 50)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entity": entity,
		"events": events,
	})
}

// Notables GET /api/v1/rba/notables
func (h *RbaHandler) ListNotables(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	notables, err := h.store.ListRbaNotables(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  notables,
		"total": len(notables),
	})
}

// ListWeights GET /api/v1/rba/weights
func (h *RbaHandler) ListWeights(w http.ResponseWriter, r *http.Request) {
	weights, err := h.store.ListRbaRuleWeights()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": weights, "total": len(weights)})
}

// SetWeight PUT /api/v1/rba/weights/:rule_id
func (h *RbaHandler) SetWeight(w http.ResponseWriter, r *http.Request) {
	ruleID, err := strconv.Atoi(chi.URLParam(r, "rule_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule_id")
		return
	}
	var req struct {
		RiskWeight  int    `json:"risk_weight"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.RiskWeight <= 0 || req.RiskWeight > 1000 {
		writeError(w, http.StatusBadRequest, "risk_weight must be 1-1000")
		return
	}
	rw := &store.RbaRuleWeight{
		RuleID:      ruleID,
		RiskWeight:  req.RiskWeight,
		Description: req.Description,
	}
	if err := h.store.UpsertRbaRuleWeight(rw); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": rw})
}

// SetThreshold PUT /api/v1/rba/entities/:id/threshold
func (h *RbaHandler) SetThreshold(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Threshold int `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Threshold < 10 || req.Threshold > 10000 {
		writeError(w, http.StatusBadRequest, "threshold must be 10-10000")
		return
	}
	entity, _ := h.store.GetRbaEntityRisk(id)
	entity.EntityID = id
	entity.Threshold = req.Threshold
	if err := h.store.UpsertRbaEntityRisk(entity); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": entity})
}
