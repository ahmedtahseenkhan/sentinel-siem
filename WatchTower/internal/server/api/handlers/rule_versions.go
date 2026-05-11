package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/watchtower/watchtower/internal/sigma"
	"github.com/watchtower/watchtower/internal/store"
)

type RuleVersionHandler struct {
	store *store.Store
}

func NewRuleVersionHandler(st *store.Store) *RuleVersionHandler {
	return &RuleVersionHandler{store: st}
}

// ListFiles GET /api/v1/rule-versions
// Returns all versioned rule files with metadata.
func (h *RuleVersionHandler) ListFiles(w http.ResponseWriter, r *http.Request) {
	files, err := h.store.ListVersionedFiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": files, "total": len(files)})
}

// ListVersions GET /api/v1/rule-versions/history?file=xxx
// Returns all versions of a specific rule file (no content — metadata only).
func (h *RuleVersionHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		writeError(w, http.StatusBadRequest, "file query param required")
		return
	}
	versions, err := h.store.ListRuleVersions(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": versions, "total": len(versions)})
}

// GetVersion GET /api/v1/rule-versions/content?file=xxx&version=2
// Returns the full YAML content of a specific version.
func (h *RuleVersionHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	ver, _ := strconv.Atoi(r.URL.Query().Get("version"))
	if file == "" || ver <= 0 {
		writeError(w, http.StatusBadRequest, "file and version query params required")
		return
	}
	rv, err := h.store.GetRuleVersion(file, ver)
	if err != nil {
		writeError(w, http.StatusNotFound, "version not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": rv})
}

// SaveVersion POST /api/v1/rule-versions
// Saves a new version of a rule file.
func (h *RuleVersionHandler) SaveVersion(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File      string `json:"file"`
		Content   string `json:"content"`
		CommitMsg string `json:"commit_msg"`
		Author    string `json:"author"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.File == "" || req.Content == "" {
		writeError(w, http.StatusBadRequest, "file and content are required")
		return
	}
	if req.CommitMsg == "" {
		req.CommitMsg = "Manual update"
	}
	if req.Author == "" {
		req.Author = "system"
	}

	rv, err := h.store.SaveRuleVersion(req.File, req.Content, req.CommitMsg, req.Author)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": rv})
}

// Diff GET /api/v1/rule-versions/diff?file=xxx&v1=1&v2=2
// Returns a unified diff between two versions of a rule file.
func (h *RuleVersionHandler) Diff(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	v1, _ := strconv.Atoi(r.URL.Query().Get("v1"))
	v2, _ := strconv.Atoi(r.URL.Query().Get("v2"))
	if file == "" || v1 <= 0 || v2 <= 0 {
		writeError(w, http.StatusBadRequest, "file, v1, and v2 query params required")
		return
	}
	rv1, err := h.store.GetRuleVersion(file, v1)
	if err != nil {
		writeError(w, http.StatusNotFound, "version v1 not found")
		return
	}
	rv2, err := h.store.GetRuleVersion(file, v2)
	if err != nil {
		writeError(w, http.StatusNotFound, "version v2 not found")
		return
	}

	diff := unifiedDiff(rv1.Content, rv2.Content, v1, v2)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"file": file,
		"v1":   v1,
		"v2":   v2,
		"diff": diff,
	})
}

// Validate POST /api/v1/rule-versions/validate
// Validates YAML syntax and Sigma rule structure without saving.
func (h *RuleVersionHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	_, err := sigma.Parse([]byte(req.Content))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"errors":  []string{},
		"message": "Rule is valid Sigma YAML",
	})
}

// unifiedDiff produces a simple line-diff between two text blobs.
func unifiedDiff(a, b string, v1, v2 int) []map[string]interface{} {
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")

	var diff []map[string]interface{}
	maxLen := len(linesA)
	if len(linesB) > maxLen {
		maxLen = len(linesB)
	}

	for i := 0; i < maxLen; i++ {
		la, lb := "", ""
		if i < len(linesA) {
			la = linesA[i]
		}
		if i < len(linesB) {
			lb = linesB[i]
		}
		lineNum := i + 1
		if la == lb {
			diff = append(diff, map[string]interface{}{
				"type": "equal", "line": lineNum, "content": la,
			})
		} else {
			if la != "" {
				diff = append(diff, map[string]interface{}{
					"type": "removed", "line": lineNum, "content": la, "version": v1,
				})
			}
			if lb != "" {
				diff = append(diff, map[string]interface{}{
					"type": "added", "line": lineNum, "content": lb, "version": v2,
				})
			}
		}
	}
	return diff
}
