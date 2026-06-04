package handlers

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/watchtower/watchtower/internal/store"
)

const maxArtifactBytes = 100 << 20 // 100 MB

var reSafeID = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// ArtifactHandler ingests agent-uploaded forensic bundles and serves them back
// to operators.
type ArtifactHandler struct {
	store       *store.Store
	dir         string
	enrollToken string
}

func NewArtifactHandler(st *store.Store, dir, enrollToken string) *ArtifactHandler {
	if dir == "" {
		dir = "/var/lib/watchtower/artifacts"
	}
	return &ArtifactHandler{store: st, dir: dir, enrollToken: enrollToken}
}

// Upload POST /ingest/artifact/{agent_id}
// Authenticated by the enroll token (agents don't hold the API key). Body is the
// raw zip bundle.
func (h *ArtifactHandler) Upload(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Enroll-Token")
	if h.enrollToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(h.enrollToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid enroll token")
		return
	}
	agentID := reSafeID.ReplaceAllString(chi.URLParam(r, "agent_id"), "_")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "storage unavailable")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxArtifactBytes))
	if err != nil || len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty or unreadable upload")
		return
	}
	now := time.Now()
	fn := fmt.Sprintf("%s_%d.zip", agentID, now.Unix())
	path := filepath.Join(h.dir, fn)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store artifact")
		return
	}
	id, err := h.store.InsertArtifact(&store.Artifact{
		AgentID:   agentID,
		Filename:  fn,
		Path:      path,
		SizeBytes: int64(len(data)),
		CreatedAt: now.UnixMilli(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"id": id, "filename": fn, "size_bytes": len(data)})
}

// List GET /api/v1/artifacts?agent_id=&limit=
func (h *ArtifactHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.store.ListArtifacts(r.URL.Query().Get("agent_id"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": items, "total": len(items)})
}

// Download GET /api/v1/artifacts/{id}/download
func (h *ArtifactHandler) Download(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	a, err := h.store.GetArtifact(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	f, err := os.Open(a.Path)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact file missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+a.Filename+"\"")
	_, _ = io.Copy(w, f)
}
