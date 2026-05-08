package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/watchtower/watchtower/internal/engine/decoder"
	"github.com/watchtower/watchtower/internal/models"
)

type DecoderHandler struct {
	manager *decoder.Manager
}

func NewDecoderHandler(m *decoder.Manager) *DecoderHandler {
	return &DecoderHandler{manager: m}
}

func (h *DecoderHandler) List(w http.ResponseWriter, r *http.Request) {
	decoders := h.manager.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  decoders,
		"total": len(decoders),
	})
}

func (h *DecoderHandler) Create(w http.ResponseWriter, r *http.Request) {
	var dec models.Decoder
	if err := json.NewDecoder(r.Body).Decode(&dec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if dec.Name == "" {
		writeError(w, http.StatusBadRequest, "decoder name is required")
		return
	}
	if err := h.manager.Add(dec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid decoder: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": dec})
}
