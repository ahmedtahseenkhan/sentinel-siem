package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/registry"
)

type GroupHandler struct {
	registry *registry.Registry
}

func NewGroupHandler(reg *registry.Registry) *GroupHandler {
	return &GroupHandler{registry: reg}
}

func (h *GroupHandler) List(w http.ResponseWriter, r *http.Request) {
	groups, err := h.registry.ListGroups()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": groups, "total": len(groups)})
}

func (h *GroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	group, err := h.registry.CreateGroup(body.Name, body.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": group})
}

func (h *GroupHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, err := h.registry.GetGroup(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": group})
}

func (h *GroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.registry.DeleteGroup(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "group deleted"})
}
