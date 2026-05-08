package middleware

import (
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// RequestLogger logs each request with its correlation (request) ID, method,
// path, status code, response size, and latency. The request ID is sourced
// from chi's RequestID middleware and echoed back in the X-Request-ID header
// so clients can correlate dashboard requests to server-side log entries.
func RequestLogger(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := chimiddleware.GetReqID(r.Context())

			// Echo the request ID so the dashboard / curl caller can correlate.
			w.Header().Set("X-Request-ID", reqID)

			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)

			logger.Info("api request",
				zap.String("request_id", reqID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("status", rw.status),
				zap.Int("response_bytes", rw.size),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}
