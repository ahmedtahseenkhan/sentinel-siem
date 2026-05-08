package api

import (
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

type wrappedResponseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *wrappedResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *wrappedResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

// requestLogger returns a chi-compatible middleware that logs each request
// with its correlation ID, method, path, status, and duration.
func requestLogger(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := chimiddleware.GetReqID(r.Context())
			w.Header().Set("X-Request-ID", reqID)

			rw := &wrappedResponseWriter{ResponseWriter: w, status: http.StatusOK}
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
