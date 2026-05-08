package middleware

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/audit"
)

// responseRecorder wraps http.ResponseWriter to capture the status code.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}

// AuditLog returns a middleware that records every request going through the
// router to the provided audit.Logger. Sensitive headers (Authorization) are
// never logged. Health endpoints are skipped to avoid noisy audit streams.
func AuditLog(al *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip health checks — they are high-frequency and not security-relevant.
			if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/health/") {
				next.ServeHTTP(w, r)
				return
			}

			rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rr, r)
			elapsed := time.Since(start).Milliseconds()

			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			al.Log(audit.Record{
				EventType:  audit.EventTypeAPICall,
				ActorIP:    ip,
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: rr.status,
				DurationMs: elapsed,
				Success:    rr.status < 400,
			})
		})
	}
}
