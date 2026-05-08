package handlers

import (
	"net/http"
	"runtime"
	"time"

	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/store"
)

var startTime = time.Now()

type SystemHandler struct {
	registry *registry.Registry
	store    *store.Store
}

func NewSystemHandler(reg *registry.Registry, st *store.Store) *SystemHandler {
	return &SystemHandler{registry: reg, store: st}
}

func (h *SystemHandler) Status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "running",
		"version": "0.1.0",
		"uptime":  time.Since(startTime).String(),
	})
}

func (h *SystemHandler) Stats(w http.ResponseWriter, r *http.Request) {
	total, active, disconnected, _ := h.registry.CountAgents()
	alertCount, _ := h.store.CountAlerts()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agents": map[string]int{
			"total":        total,
			"active":       active,
			"disconnected": disconnected,
		},
		"alerts": map[string]int{
			"total": alertCount,
		},
		"memory": map[string]interface{}{
			"alloc_mb":       mem.Alloc / 1024 / 1024,
			"sys_mb":         mem.Sys / 1024 / 1024,
			"num_goroutines": runtime.NumGoroutine(),
		},
	})
}

func Health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
	}
}

// Ready returns 200 when the service has finished startup and is ready to serve
// traffic, or 503 during initialisation. Kubernetes uses this for readinessProbe.
func Ready(store *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"status": "not_ready",
				"reason": "store unavailable",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ready",
			"uptime":  time.Since(startTime).String(),
		})
	}
}
