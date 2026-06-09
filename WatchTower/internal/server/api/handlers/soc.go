package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
)

// SOCHandler serves the SOC roster/schedule plus manager metrics and FP stats.
type SOCHandler struct {
	store *store.Store
}

func NewSOCHandler(st *store.Store) *SOCHandler { return &SOCHandler{store: st} }

// ListEngineers GET /api/v1/soc/engineers?active=true
func (h *SOCHandler) ListEngineers(w http.ResponseWriter, r *http.Request) {
	active := r.URL.Query().Get("active") == "true"
	engs, err := h.store.ListSOCEngineers(active)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": engs, "total": len(engs)})
}

// UpsertEngineer POST /api/v1/soc/engineers
func (h *SOCHandler) UpsertEngineer(w http.ResponseWriter, r *http.Request) {
	var e models.SOCEngineer
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if e.SamAccount == "" {
		writeError(w, http.StatusBadRequest, "sam_account is required")
		return
	}
	if e.SkillGroups == nil {
		e.SkillGroups = []string{}
	}
	if err := h.store.UpsertSOCEngineer(&e); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": e})
}

// DeleteEngineer DELETE /api/v1/soc/engineers/{sam}
func (h *SOCHandler) DeleteEngineer(w http.ResponseWriter, r *http.Request) {
	sam := chi.URLParam(r, "sam")
	if err := h.store.DeleteSOCEngineer(sam); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "engineer removed"})
}

// ListShifts GET /api/v1/soc/shifts?sam=
func (h *SOCHandler) ListShifts(w http.ResponseWriter, r *http.Request) {
	shifts, err := h.store.ListSOCShifts(r.URL.Query().Get("sam"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": shifts, "total": len(shifts)})
}

// AddShift POST /api/v1/soc/shifts
func (h *SOCHandler) AddShift(w http.ResponseWriter, r *http.Request) {
	var sh models.SOCShift
	if err := json.NewDecoder(r.Body).Decode(&sh); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if sh.SamAccount == "" {
		writeError(w, http.StatusBadRequest, "sam_account is required")
		return
	}
	id, err := h.store.AddSOCShift(&sh)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sh.ID = id
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": sh})
}

// DeleteShift DELETE /api/v1/soc/shifts/{id}
func (h *SOCHandler) DeleteShift(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.store.DeleteSOCShift(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "shift removed"})
}

// Metrics GET /api/v1/cases/metrics?window_hours=168
func (h *SOCHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("window_hours"))
	if hours <= 0 {
		hours = 168 // 7 days
	}
	m, err := h.store.CaseMetrics(int64(hours) * 3600 * 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": m})
}

// FPStats GET /api/v1/cases/fp-stats?limit=20
func (h *SOCHandler) FPStats(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	stats, err := h.store.FPRuleStats(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": stats, "total": len(stats)})
}
