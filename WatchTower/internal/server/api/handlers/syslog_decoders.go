package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/engine/decoder"
)

// SyslogDecoderProvider is satisfied by *api.Server (avoids import cycle).
type SyslogDecoderProvider interface {
	SyslogDecoder() *decoder.SyslogEngine
}

// SyslogDecoderHandler manages the Wazuh-like syslog decoder pipeline via REST.
type SyslogDecoderHandler struct {
	provider SyslogDecoderProvider
}

func NewSyslogDecoderHandler(p SyslogDecoderProvider) *SyslogDecoderHandler {
	return &SyslogDecoderHandler{provider: p}
}

func (h *SyslogDecoderHandler) engine() *decoder.SyslogEngine {
	return h.provider.SyslogDecoder()
}

// List returns all loaded syslog decoder rules.
func (h *SyslogDecoderHandler) List(w http.ResponseWriter, r *http.Request) {
	e := h.engine()
	if e == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog decoder engine not initialised")
		return
	}
	rules := e.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  rules,
		"total": len(rules),
	})
}

// Create adds a new custom syslog decoder rule.
func (h *SyslogDecoderHandler) Create(w http.ResponseWriter, r *http.Request) {
	e := h.engine()
	if e == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog decoder engine not initialised")
		return
	}
	var rule decoder.SyslogRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if rule.Name == "" {
		writeError(w, http.StatusBadRequest, "decoder name is required")
		return
	}
	if err := e.AddCustom(rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid decoder: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": rule})
}

// Delete removes a custom syslog decoder rule by name.
func (h *SyslogDecoderHandler) Delete(w http.ResponseWriter, r *http.Request) {
	e := h.engine()
	if e == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog decoder engine not initialised")
		return
	}
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "decoder name is required")
		return
	}
	if err := e.DeleteCustom(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "deleted"})
}

// Test runs the decoder pipeline against a sample message.
func (h *SyslogDecoderHandler) Test(w http.ResponseWriter, r *http.Request) {
	e := h.engine()
	if e == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog decoder engine not initialised")
		return
	}
	var req struct {
		AppName string `json:"app_name"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	result := e.Test(req.AppName, req.Message)
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": result})
}

// Reload forces a reload of all decoder files from disk.
func (h *SyslogDecoderHandler) Reload(w http.ResponseWriter, r *http.Request) {
	e := h.engine()
	if e == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog decoder engine not initialised")
		return
	}
	if err := e.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "reloaded",
		"total":   e.Count(),
	})
}
