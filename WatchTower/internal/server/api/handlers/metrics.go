package handlers

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// MetricsSource collects stats from the forwarder and registry for the metrics endpoint.
type MetricsSource interface {
	// ForwarderStats returns (droppedEvents, droppedAlerts, dlqDepth).
	ForwarderStats() (int64, int64, int64)
	// AgentCounts returns (total, active, disconnected, never_connected).
	AgentCounts() (int, int, int, int)
	// AlertCount returns total alerts stored.
	AlertCount() int
}

var metricsStartTime = time.Now()

// Metrics returns a Prometheus text-format exposition of key WatchTower metrics.
// No external dependency required — we write the text format by hand.
func Metrics(src MetricsSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		droppedEvents, droppedAlerts, dlqDepth := int64(0), int64(0), int64(0)
		totalAgents, activeAgents, disconnectedAgents := 0, 0, 0
		alertCount := 0
		if src != nil {
			droppedEvents, droppedAlerts, dlqDepth = src.ForwarderStats()
			totalAgents, activeAgents, disconnectedAgents, _ = src.AgentCounts()
			alertCount = src.AlertCount()
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP watchtower_up Service liveness (1 = running).\n")
		fmt.Fprintf(w, "# TYPE watchtower_up gauge\n")
		fmt.Fprintf(w, "watchtower_up 1\n\n")

		fmt.Fprintf(w, "# HELP watchtower_uptime_seconds Seconds since the process started.\n")
		fmt.Fprintf(w, "# TYPE watchtower_uptime_seconds counter\n")
		fmt.Fprintf(w, "watchtower_uptime_seconds %.0f\n\n", time.Since(metricsStartTime).Seconds())

		fmt.Fprintf(w, "# HELP watchtower_agents_total Total registered agents.\n")
		fmt.Fprintf(w, "# TYPE watchtower_agents_total gauge\n")
		fmt.Fprintf(w, "watchtower_agents_total %d\n", totalAgents)
		fmt.Fprintf(w, "watchtower_agents_active %d\n", activeAgents)
		fmt.Fprintf(w, "watchtower_agents_disconnected %d\n\n", disconnectedAgents)

		fmt.Fprintf(w, "# HELP watchtower_alerts_total Total alerts stored in the local store.\n")
		fmt.Fprintf(w, "# TYPE watchtower_alerts_total counter\n")
		fmt.Fprintf(w, "watchtower_alerts_total %d\n\n", alertCount)

		fmt.Fprintf(w, "# HELP watchtower_forwarder_dropped_events_total Events dropped due to full channel.\n")
		fmt.Fprintf(w, "# TYPE watchtower_forwarder_dropped_events_total counter\n")
		fmt.Fprintf(w, "watchtower_forwarder_dropped_events_total %d\n\n", droppedEvents)

		fmt.Fprintf(w, "# HELP watchtower_forwarder_dropped_alerts_total Alerts dropped due to full channel.\n")
		fmt.Fprintf(w, "# TYPE watchtower_forwarder_dropped_alerts_total counter\n")
		fmt.Fprintf(w, "watchtower_forwarder_dropped_alerts_total %d\n\n", droppedAlerts)

		fmt.Fprintf(w, "# HELP watchtower_forwarder_dlq_depth Dead-letter queue depth (failed batches).\n")
		fmt.Fprintf(w, "# TYPE watchtower_forwarder_dlq_depth gauge\n")
		fmt.Fprintf(w, "watchtower_forwarder_dlq_depth %d\n\n", dlqDepth)

		fmt.Fprintf(w, "# HELP process_resident_memory_bytes Resident memory in bytes.\n")
		fmt.Fprintf(w, "# TYPE process_resident_memory_bytes gauge\n")
		fmt.Fprintf(w, "process_resident_memory_bytes %d\n\n", mem.Sys)

		fmt.Fprintf(w, "# HELP go_goroutines Number of active goroutines.\n")
		fmt.Fprintf(w, "# TYPE go_goroutines gauge\n")
		fmt.Fprintf(w, "go_goroutines %d\n", runtime.NumGoroutine())
	}
}
