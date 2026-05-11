package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
)

type PlaybookHandler struct {
	store *store.Store
}

func NewPlaybookHandler(st *store.Store) *PlaybookHandler {
	return &PlaybookHandler{store: st}
}

// List GET /api/v1/playbooks
func (h *PlaybookHandler) List(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "true"
	pbs, err := h.store.ListPlaybooks(!all)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": pbs, "total": len(pbs)})
}

// Get GET /api/v1/playbooks/:id
func (h *PlaybookHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid playbook id")
		return
	}
	pb, err := h.store.GetPlaybook(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": pb})
}

// Create POST /api/v1/playbooks
func (h *PlaybookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string                    `json:"name"`
		Description string                    `json:"description"`
		Enabled     *bool                     `json:"enabled"`
		Trigger     models.PlaybookTrigger    `json:"trigger"`
		Actions     []models.PlaybookAction   `json:"actions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	pb := &models.Playbook{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     enabled,
		Trigger:     req.Trigger,
		Actions:     req.Actions,
	}
	if pb.Actions == nil {
		pb.Actions = []models.PlaybookAction{}
	}
	id, err := h.store.CreatePlaybook(pb)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pb.ID = id
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": pb})
}

// Update PUT /api/v1/playbooks/:id
func (h *PlaybookHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid playbook id")
		return
	}
	pb, err := h.store.GetPlaybook(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "playbook not found")
		return
	}
	if err := json.NewDecoder(r.Body).Decode(pb); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pb.ID = id
	if err := h.store.UpdatePlaybook(pb); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _ := h.store.GetPlaybook(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": updated})
}

// Delete DELETE /api/v1/playbooks/:id
func (h *PlaybookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid playbook id")
		return
	}
	if err := h.store.DeletePlaybook(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "playbook deleted"})
}

// ListExecutions GET /api/v1/playbooks/:id/executions
func (h *PlaybookHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	execs, err := h.store.ListExecutions(id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": execs, "total": len(execs)})
}

// AllExecutions GET /api/v1/playbook-executions
func (h *PlaybookHandler) AllExecutions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	execs, err := h.store.ListExecutions(0, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": execs, "total": len(execs)})
}
