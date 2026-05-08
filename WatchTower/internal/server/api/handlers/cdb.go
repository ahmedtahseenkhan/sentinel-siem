package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/engine/cdb"
)

type CDBHandler struct {
	manager *cdb.Manager
}

func NewCDBHandler(m *cdb.Manager) *CDBHandler {
	return &CDBHandler{manager: m}
}

func (h *CDBHandler) List(w http.ResponseWriter, r *http.Request) {
	names := h.manager.ListNames()
	lists := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		list := h.manager.GetList(name)
		if list != nil {
			lists = append(lists, map[string]interface{}{
				"name":    name,
				"entries": list.Count(),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": lists, "total": len(lists)})
}

func (h *CDBHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	list := h.manager.GetList(name)
	if list == nil {
		writeError(w, http.StatusNotFound, "list not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":    name,
		"entries": list.Entries(),
		"count":   list.Count(),
	})
}

func (h *CDBHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string            `json:"name"`
		Entries map[string]string `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	list := cdb.NewList(body.Name)
	for k, v := range body.Entries {
		list.Add(k, v)
	}
	h.manager.AddList(list)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"name":  body.Name,
		"count": list.Count(),
	})
}
