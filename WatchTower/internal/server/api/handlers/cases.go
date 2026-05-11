package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
)

type CaseHandler struct {
	store *store.Store
}

func NewCaseHandler(st *store.Store) *CaseHandler {
	return &CaseHandler{store: st}
}

// List GET /api/v1/cases
func (h *CaseHandler) List(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	priority := r.URL.Query().Get("priority")
	assignee := r.URL.Query().Get("assignee")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 100
	}

	cases, err := h.store.ListCases(status, priority, assignee, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, open, investigating, resolved, err := h.store.CountCases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":         cases,
		"total":        total,
		"open":         open,
		"investigating": investigating,
		"resolved":     resolved,
	})
}

// Get GET /api/v1/cases/:id
func (h *CaseHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	c, err := h.store.GetCase(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": c})
}

// Create POST /api/v1/cases
func (h *CaseHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title       string          `json:"title"`
		Description string          `json:"description"`
		Priority    string          `json:"priority"`
		Severity    int             `json:"severity"`
		Assignee    string          `json:"assignee"`
		CreatedBy   string          `json:"created_by"`
		Tags        []string        `json:"tags"`
		AlertIDs    []int64         `json:"alert_ids"`
		AgentIDs    []string        `json:"agent_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}

	c := &models.Case{
		Title:       req.Title,
		Description: req.Description,
		Status:      models.CaseStatusOpen,
		Priority:    models.CasePriority(req.Priority),
		Severity:    req.Severity,
		Assignee:    req.Assignee,
		CreatedBy:   req.CreatedBy,
		Tags:        req.Tags,
		AlertIDs:    req.AlertIDs,
		AgentIDs:    req.AgentIDs,
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	if c.AlertIDs == nil {
		c.AlertIDs = []int64{}
	}
	if c.AgentIDs == nil {
		c.AgentIDs = []string{}
	}

	id, err := h.store.CreateCase(c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.ID = id
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": c})
}

// Update PUT /api/v1/cases/:id
func (h *CaseHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}

	existing, err := h.store.GetCase(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Status      string   `json:"status"`
		Priority    string   `json:"priority"`
		Severity    int      `json:"severity"`
		Assignee    string   `json:"assignee"`
		Tags        []string `json:"tags"`
		AlertIDs    []int64  `json:"alert_ids"`
		AgentIDs    []string `json:"agent_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Patch — only override if provided
	title := existing.Title
	if req.Title != "" {
		title = req.Title
	}
	description := existing.Description
	if req.Description != "" {
		description = req.Description
	}
	status := string(existing.Status)
	if req.Status != "" {
		status = req.Status
	}
	priority := string(existing.Priority)
	if req.Priority != "" {
		priority = req.Priority
	}
	severity := existing.Severity
	if req.Severity > 0 {
		severity = req.Severity
	}
	assignee := existing.Assignee
	if req.Assignee != "" {
		assignee = req.Assignee
	}
	tags := existing.Tags
	if req.Tags != nil {
		tags = req.Tags
	}
	alertIDs := existing.AlertIDs
	if req.AlertIDs != nil {
		alertIDs = req.AlertIDs
	}
	agentIDs := existing.AgentIDs
	if req.AgentIDs != nil {
		agentIDs = req.AgentIDs
	}

	if err := h.store.UpdateCase(id, title, description, status, priority, assignee, severity, tags, alertIDs, agentIDs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	updated, _ := h.store.GetCase(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": updated})
}

// Delete DELETE /api/v1/cases/:id
func (h *CaseHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	if err := h.store.DeleteCase(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "case deleted"})
}

// AddNote POST /api/v1/cases/:id/notes
func (h *CaseHandler) AddNote(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var req struct {
		Author  string `json:"author"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}
	note := &models.CaseNote{
		CaseID:  id,
		Author:  req.Author,
		Content: req.Content,
	}
	noteID, err := h.store.AddCaseNote(note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	note.ID = noteID
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": note})
}

// ListNotes GET /api/v1/cases/:id/notes
func (h *CaseHandler) ListNotes(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	notes, err := h.store.ListCaseNotes(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": notes, "total": len(notes)})
}

// AddEvidence POST /api/v1/cases/:id/evidence
func (h *CaseHandler) AddEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var req struct {
		Title   string `json:"title"`
		Type    string `json:"type"`
		Content string `json:"content"`
		AddedBy string `json:"added_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ev := &models.CaseEvidence{
		CaseID:  id,
		Title:   req.Title,
		Type:    req.Type,
		Content: req.Content,
		AddedBy: req.AddedBy,
	}
	if ev.Type == "" {
		ev.Type = "log"
	}
	evID, err := h.store.AddCaseEvidence(ev)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ev.ID = evID
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": ev})
}

// ListEvidence GET /api/v1/cases/:id/evidence
func (h *CaseHandler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	evidence, err := h.store.ListCaseEvidence(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": evidence, "total": len(evidence)})
}
