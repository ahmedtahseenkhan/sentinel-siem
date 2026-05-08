package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/watchtower/watchtower/internal/sigma"
)

const maxSigmaBodyBytes = 256 * 1024 // 256 KB

// SigmaHandler exposes Sigma rule conversion.
type SigmaHandler struct{}

func NewSigmaHandler() *SigmaHandler { return &SigmaHandler{} }

// Convert accepts a raw Sigma YAML rule in the request body and returns the
// equivalent WatchTower rule as JSON. The converted rule is NOT automatically
// stored — callers that want to persist it should POST to /api/v1/rules.
//
//	POST /api/v1/sigma/convert
//	Content-Type: application/yaml   (body = raw Sigma YAML)
//
//	200 OK — { "rule": {...} }
//	400 Bad Request — { "error": "..." }
func (h *SigmaHandler) Convert(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSigmaBodyBytes))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read request body")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "request body must contain a Sigma YAML rule")
		return
	}

	rule, err := sigma.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"rule": rule})
}

// ConvertAndStore converts a Sigma rule and immediately adds it to the running
// engine so it takes effect without a restart.
//
//	POST /api/v1/sigma/import
//	Content-Type: application/yaml
func (h *SigmaHandler) ConvertAndStore(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSigmaBodyBytes))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read request body")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "request body must contain a Sigma YAML rule")
		return
	}

	rule, err := sigma.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Return the converted rule; the caller can use /api/v1/rules to persist it.
	resp, _ := json.Marshal(map[string]interface{}{
		"rule":    rule,
		"message": "converted successfully; POST to /api/v1/rules to persist",
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp) //nolint:errcheck
}
