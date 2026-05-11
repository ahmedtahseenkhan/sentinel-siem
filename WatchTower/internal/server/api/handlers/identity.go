package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
)

// LDAPSyncer is satisfied by *identity.Manager.
type LDAPSyncer interface {
	Sync() error
}

type IdentityHandler struct {
	store  *store.Store
	syncer LDAPSyncer // nil when LDAP not configured
}

func NewIdentityHandler(st *store.Store, syncer LDAPSyncer) *IdentityHandler {
	return &IdentityHandler{store: st, syncer: syncer}
}

// List GET /api/v1/identity/users
func (h *IdentityHandler) List(w http.ResponseWriter, r *http.Request) {
	dept       := r.URL.Query().Get("department")
	enabledStr := r.URL.Query().Get("enabled")
	limit, _   := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _  := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 200
	}
	enabledOnly := enabledStr == "true"

	users, err := h.store.ListIdentityUsers(dept, enabledOnly, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, enabled, _ := h.store.CountIdentityUsers()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":    users,
		"total":   total,
		"enabled": enabled,
	})
}

// Get GET /api/v1/identity/users/:sam
func (h *IdentityHandler) Get(w http.ResponseWriter, r *http.Request) {
	sam := chi.URLParam(r, "sam")
	u, err := h.store.GetIdentityUser(sam)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": u})
}

// Create POST /api/v1/identity/users  (manual user add)
func (h *IdentityHandler) Create(w http.ResponseWriter, r *http.Request) {
	var u models.IdentityUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if u.SamAccount == "" {
		writeError(w, http.StatusBadRequest, "sam_account is required")
		return
	}
	u.Source = "manual"
	u.Enabled = true
	if err := h.store.UpsertIdentityUser(&u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved, _ := h.store.GetIdentityUser(u.SamAccount)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": saved})
}

// Delete DELETE /api/v1/identity/users/:sam
func (h *IdentityHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sam := chi.URLParam(r, "sam")
	if err := h.store.DeleteIdentityUser(sam); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "user deleted"})
}

// Sync POST /api/v1/identity/sync  — trigger immediate LDAP sync
func (h *IdentityHandler) Sync(w http.ResponseWriter, r *http.Request) {
	if h.syncer == nil {
		writeError(w, http.StatusServiceUnavailable, "LDAP not configured (set WATCHTOWER_LDAP_URL)")
		return
	}
	if err := h.syncer.Sync(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, _, _ := h.store.CountIdentityUsers()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "sync complete",
		"total":   total,
	})
}

// Status GET /api/v1/identity/status
func (h *IdentityHandler) Status(w http.ResponseWriter, r *http.Request) {
	total, enabled, _ := h.store.CountIdentityUsers()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ldap_configured": h.syncer != nil,
		"total_users":     total,
		"enabled_users":   enabled,
	})
}
