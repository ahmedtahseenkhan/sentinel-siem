package api

import (
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/watchtower/watchtower/internal/server/api/handlers"
	"github.com/watchtower/watchtower/internal/server/api/middleware"
)

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.RequestLogger(s.logger))
	r.Use(middleware.CORS())

	r.Use(middleware.RateLimit(s.cfg.RateLimit.RPS, s.cfg.RateLimit.Burst))
	r.Use(middleware.AuditLog(s.audit))

	r.Get("/health", handlers.Health())
	r.Get("/ready", handlers.Ready(s.store))
	r.Get("/metrics", handlers.Metrics(nil))

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(s.cfg.Auth.APIKey))

		ah := handlers.NewAgentHandler(s.registry)
		r.Route("/agents", func(r chi.Router) {
			r.Get("/", ah.List)
			r.Get("/{id}", ah.Get)
			r.Delete("/{id}", ah.Delete)
			r.Put("/{id}/group", ah.AssignGroup)
			r.Post("/{id}/config", ah.PushConfig)
		})

		gh := handlers.NewGroupHandler(s.registry)
		r.Route("/groups", func(r chi.Router) {
			r.Get("/", gh.List)
			r.Post("/", gh.Create)
			r.Get("/{id}", gh.Get)
			r.Delete("/{id}", gh.Delete)
		})

		alh := handlers.NewAlertHandler(s.store)
		r.Route("/alerts", func(r chi.Router) {
			r.Get("/", alh.List)
		})

		arh := handlers.NewActiveResponseHandler(s.registry, s.store)
		r.Post("/active-response", arh.Trigger)

		sh := handlers.NewSystemHandler(s.registry, s.store)
		r.Get("/status", sh.Status)
		r.Get("/stats", sh.Stats)

		rh := handlers.NewRuleHandler(s.engine.Rules())
		r.Route("/rules", func(r chi.Router) {
			r.Get("/", rh.List)
			r.Get("/{id}", rh.Get)
			r.Post("/", rh.Create)
		})

		dh := handlers.NewDecoderHandler(s.engine.Decoders())
		r.Route("/decoders", func(r chi.Router) {
			r.Get("/", dh.List)
			r.Post("/", dh.Create)
		})

		ch := handlers.NewCDBHandler(s.engine.CDB())
		r.Route("/cdb-lists", func(r chi.Router) {
			r.Get("/", ch.List)
			r.Get("/{name}", ch.Get)
			r.Post("/", ch.Create)
		})

		scah := handlers.NewSCAHandler(s.store)
		r.Route("/sca/{agent_id}", func(r chi.Router) {
			r.Get("/", scah.GetByAgent)
			r.Get("/policies", scah.ListPolicies)
		})

		sysh := handlers.NewSyscollectorHandler(s.store)
		r.Route("/syscollector/{agent_id}", func(r chi.Router) {
			r.Get("/hardware", sysh.Hardware)
			r.Get("/os", sysh.OS)
			r.Get("/packages", sysh.Packages)
			r.Get("/ports", sysh.Ports)
			r.Get("/netif", sysh.NetInterfaces)
		})

		sigh := handlers.NewSigmaHandler()
		r.Route("/sigma", func(r chi.Router) {
			r.Post("/convert", sigh.Convert)
			r.Post("/import", sigh.ConvertAndStore)
		})

		csh := handlers.NewCaseHandler(s.store)
		r.Route("/cases", func(r chi.Router) {
			r.Get("/", csh.List)
			r.Post("/", csh.Create)
			r.Get("/{id}", csh.Get)
			r.Put("/{id}", csh.Update)
			r.Delete("/{id}", csh.Delete)
			r.Get("/{id}/notes", csh.ListNotes)
			r.Post("/{id}/notes", csh.AddNote)
			r.Get("/{id}/evidence", csh.ListEvidence)
			r.Post("/{id}/evidence", csh.AddEvidence)
		})
	})

	return r
}
