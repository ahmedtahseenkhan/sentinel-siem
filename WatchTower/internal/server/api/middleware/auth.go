package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// APIKeyAuth enforces mandatory API key authentication via the Authorization:
// Bearer header only. Query-string delivery is intentionally omitted because
// query parameters appear in access logs, proxy caches, and browser history.
func APIKeyAuth(validKey string) func(http.Handler) http.Handler {
	if validKey == "" {
		panic("APIKeyAuth: validKey must not be empty")
	}
	validKeyBytes := []byte(validKey)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			if raw == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			key := strings.TrimPrefix(raw, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(key), validKeyBytes) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
