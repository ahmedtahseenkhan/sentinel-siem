package handlers

import (
	"net/http"

	"github.com/watchvault/watchvault/internal/opensearch"
	"github.com/watchvault/watchvault/internal/pipeline"
)

type HealthHandler struct {
	client   *opensearch.Client
	pipeline *pipeline.Pipeline
}

func NewHealthHandler(client *opensearch.Client, pipe *pipeline.Pipeline) *HealthHandler {
	return &HealthHandler{client: client, pipeline: pipe}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	osStatus := h.client.HealthStatus()
	if osStatus == 2 {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            status,
		"version":           "0.1.0",
		"opensearch_status": osStatus,
	})
}

func (h *HealthHandler) Stats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_indexed": h.pipeline.TotalIndexed(),
	})
}

func (h *HealthHandler) ClusterHealth(w http.ResponseWriter, r *http.Request) {
	health, err := h.client.GetClusterHealth()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": health})
}

// Ready returns 200 only when OpenSearch is reachable, 503 otherwise.
// Kubernetes readinessProbe should target this endpoint.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if err := h.client.Ping(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status": "not_ready",
			"reason": "opensearch unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ready",
		"total_indexed": h.pipeline.TotalIndexed(),
	})
}
