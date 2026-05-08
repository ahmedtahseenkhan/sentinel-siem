package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchvault/watchvault/internal/opensearch"
)

type IndexHandler struct {
	client *opensearch.Client
}

func NewIndexHandler(client *opensearch.Client) *IndexHandler {
	return &IndexHandler{client: client}
}

func (h *IndexHandler) List(w http.ResponseWriter, r *http.Request) {
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		pattern = "watchvault-*"
	}
	indices, err := h.client.ListIndices(pattern)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  indices,
		"total": len(indices),
	})
}

func (h *IndexHandler) Stats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	indices, err := h.client.ListIndices(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(indices) == 0 {
		writeError(w, http.StatusNotFound, "index not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": indices[0]})
}
