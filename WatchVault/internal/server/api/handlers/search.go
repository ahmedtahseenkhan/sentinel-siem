package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/watchvault/watchvault/internal/models"
	"github.com/watchvault/watchvault/internal/opensearch"
)

type SearchHandler struct {
	client *opensearch.Client
}

func NewSearchHandler(client *opensearch.Client) *SearchHandler {
	return &SearchHandler{client: client}
}

func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	var req models.SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Index == "" {
		writeError(w, http.StatusBadRequest, "index is required")
		return
	}
	if req.Size <= 0 {
		req.Size = 20
	}
	if req.Query == nil {
		req.Query = map[string]interface{}{"match_all": map[string]interface{}{}}
	}

	result, err := h.client.Search(&req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
