package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/store"
)

// UebaAnalyzer is satisfied by *ueba.Analyzer.
type UebaAnalyzer interface {
	Analyze()
}

type UebaHandler struct {
	store    *store.Store
	analyzer UebaAnalyzer
}

func NewUebaHandler(st *store.Store, analyzer UebaAnalyzer) *UebaHandler {
	return &UebaHandler{store: st, analyzer: analyzer}
}

// RiskScores GET /api/v1/ueba/risk-scores
// Returns entities ranked by risk score descending.
func (h *UebaHandler) RiskScores(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	scores, err := h.store.ListUebaRiskScores(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  scores,
		"total": len(scores),
	})
}

// Anomalies GET /api/v1/ueba/anomalies
// Returns recent anomalies, optionally filtered by entity.
func (h *UebaHandler) Anomalies(w http.ResponseWriter, r *http.Request) {
	entityID := r.URL.Query().Get("entity_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	anomalies, err := h.store.ListUebaAnomalies(entityID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  anomalies,
		"total": len(anomalies),
	})
}

// EntityRisk GET /api/v1/ueba/entity/:id
// Returns risk score + recent anomalies for one entity.
func (h *UebaHandler) EntityRisk(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	scores, _ := h.store.ListUebaRiskScores(500)
	var entityScore interface{}
	for _, s := range scores {
		if s.EntityID == id {
			entityScore = s
			break
		}
	}

	anomalies, err := h.store.ListUebaAnomalies(id, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entity_id": id,
		"risk":      entityScore,
		"anomalies": anomalies,
	})
}

// TriggerAnalysis POST /api/v1/ueba/analyze
// Triggers an immediate UEBA analysis cycle.
func (h *UebaHandler) TriggerAnalysis(w http.ResponseWriter, r *http.Request) {
	go h.analyzer.Analyze()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "UEBA analysis triggered — results available in ~30s",
	})
}
