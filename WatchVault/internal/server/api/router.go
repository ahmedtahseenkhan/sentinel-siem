package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/watchvault/watchvault/internal/server/api/handlers"
)

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(requestLogger(s.logger))
	r.Use(rateLimitMiddleware(s.cfg.RateLimit.RPS, s.cfg.RateLimit.Burst))

	sh := handlers.NewSearchHandler(s.client)
	ih := handlers.NewIndexHandler(s.client)
	hh := handlers.NewHealthHandler(s.client, s.pipeline)

	r.Get("/health", hh.Health)
	r.Get("/ready", hh.Ready)
	r.Get("/metrics", handlers.VaultMetrics(s.pipeline, s.client))

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(apiKeyAuth(s.cfg.Auth.APIKey))

		r.Post("/search", sh.Search)
		r.Get("/indices", ih.List)
		r.Get("/indices/{name}/stats", ih.Stats)
		r.Get("/stats", hh.Stats)
		r.Get("/cluster/health", hh.ClusterHealth)
	})

	return r
}

func apiKeyAuth(validKey string) func(http.Handler) http.Handler {
	if validKey == "" {
		panic("apiKeyAuth: validKey must not be empty")
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
