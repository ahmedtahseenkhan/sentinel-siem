package handlers

import (
	"net/http"
	"strconv"

	"github.com/watchtower/watchtower/internal/store"
)

type AlertHandler struct {
	store *store.Store
}

func NewAlertHandler(st *store.Store) *AlertHandler {
	return &AlertHandler{store: st}
}

func (h *AlertHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	minLevel, _ := strconv.Atoi(r.URL.Query().Get("min_level"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 100
	}

	alerts, err := h.store.ListAlerts(agentID, minLevel, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  alerts,
		"total": len(alerts),
	})
}
