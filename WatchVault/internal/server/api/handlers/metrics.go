package handlers

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/watchvault/watchvault/internal/opensearch"
	"github.com/watchvault/watchvault/internal/pipeline"
)

var vaultMetricsStart = time.Now()

// VaultMetrics exposes WatchVault operational metrics in Prometheus text format.
func VaultMetrics(pipe *pipeline.Pipeline, osClient *opensearch.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP watchvault_up Service liveness (1 = running).\n")
		fmt.Fprintf(w, "# TYPE watchvault_up gauge\n")
		fmt.Fprintf(w, "watchvault_up 1\n\n")

		fmt.Fprintf(w, "# HELP watchvault_uptime_seconds Seconds since the process started.\n")
		fmt.Fprintf(w, "# TYPE watchvault_uptime_seconds counter\n")
		fmt.Fprintf(w, "watchvault_uptime_seconds %.0f\n\n", time.Since(vaultMetricsStart).Seconds())

		fmt.Fprintf(w, "# HELP watchvault_indexed_total Total documents successfully indexed.\n")
		fmt.Fprintf(w, "# TYPE watchvault_indexed_total counter\n")
		fmt.Fprintf(w, "watchvault_indexed_total %d\n\n", pipe.TotalIndexed())

		fmt.Fprintf(w, "# HELP watchvault_dropped_total Documents dropped due to buffer overflow or indexing failure.\n")
		fmt.Fprintf(w, "# TYPE watchvault_dropped_total counter\n")
		fmt.Fprintf(w, "watchvault_dropped_total %d\n\n", pipe.DroppedItems())

		osStatus := int32(0)
		if osClient != nil {
			osStatus = osClient.HealthStatus()
		}
		fmt.Fprintf(w, "# HELP watchvault_opensearch_status OpenSearch cluster health (0=green,1=yellow,2=red).\n")
		fmt.Fprintf(w, "# TYPE watchvault_opensearch_status gauge\n")
		fmt.Fprintf(w, "watchvault_opensearch_status %d\n\n", osStatus)

		fmt.Fprintf(w, "# HELP process_resident_memory_bytes Resident memory in bytes.\n")
		fmt.Fprintf(w, "# TYPE process_resident_memory_bytes gauge\n")
		fmt.Fprintf(w, "process_resident_memory_bytes %d\n\n", mem.Sys)

		fmt.Fprintf(w, "# HELP go_goroutines Number of active goroutines.\n")
		fmt.Fprintf(w, "# TYPE go_goroutines gauge\n")
		fmt.Fprintf(w, "go_goroutines %d\n", runtime.NumGoroutine())
	}
}
