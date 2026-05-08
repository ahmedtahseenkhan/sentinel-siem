package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/engine/rules"
	"github.com/watchtower/watchtower/internal/models"
)

type RuleHandler struct {
	matcher *rules.Matcher
}

func NewRuleHandler(m *rules.Matcher) *RuleHandler {
	return &RuleHandler{matcher: m}
}

func (h *RuleHandler) List(w http.ResponseWriter, r *http.Request) {
	rulesList := h.matcher.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  rulesList,
		"total": len(rulesList),
	})
}

func (h *RuleHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	rule := h.matcher.Get(id)
	if rule == nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": rule})
}

func (h *RuleHandler) Create(w http.ResponseWriter, r *http.Request) {
	var rule models.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if rule.ID == 0 {
		writeError(w, http.StatusBadRequest, "rule id is required")
		return
	}
	rule.Enabled = true
	if err := h.matcher.Add(rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": rule})
}
