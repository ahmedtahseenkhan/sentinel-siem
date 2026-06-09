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

	// Agent forensic-artifact upload — authenticated by the enroll token (agents
	// hold it, not the API key), so it lives outside the /api/v1 API-key group.
	arth := handlers.NewArtifactHandler(s.store, s.artifactDir, s.enrollToken)
	r.Post("/ingest/artifact/{agent_id}", arth.Upload)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(s.cfg.Auth.APIKey))

		r.Route("/artifacts", func(r chi.Router) {
			r.Get("/", arth.List)
			r.Get("/{id}/download", arth.Download)
		})

		ah := handlers.NewAgentHandler(s.registry)
		r.Route("/agents", func(r chi.Router) {
			r.Get("/", ah.List)
			r.Post("/config", ah.PushConfigBulk)
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

			// Wazuh-like syslog decoder pipeline — program/prematch/regex/parent chaining.
			sdh := handlers.NewSyslogDecoderHandler(s)
			r.Route("/syslog", func(r chi.Router) {
				r.Get("/", sdh.List)
				r.Post("/", sdh.Create)
				r.Delete("/{name}", sdh.Delete)
				r.Post("/test", sdh.Test)
				r.Post("/reload", sdh.Reload)
			})
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

		rbah := handlers.NewRbaHandler(s.store)
		r.Route("/rba", func(r chi.Router) {
			r.Get("/entities", rbah.ListEntities)
			r.Post("/entities/purge", rbah.PurgeEntities)
			r.Get("/entities/{id}", rbah.GetEntity)
			r.Put("/entities/{id}/threshold", rbah.SetThreshold)
			r.Get("/notables", rbah.ListNotables)
			r.Get("/weights", rbah.ListWeights)
			r.Put("/weights/{rule_id}", rbah.SetWeight)
			r.Delete("/weights/{rule_id}", rbah.DeleteWeight)
		})

		uebah := handlers.NewUebaHandler(s.store, s.uebaAnalyzer)
		r.Route("/ueba", func(r chi.Router) {
			r.Get("/risk-scores", uebah.RiskScores)
			r.Get("/anomalies", uebah.Anomalies)
			r.Get("/entity/{id}", uebah.EntityRisk)
			r.Post("/analyze", uebah.TriggerAnalysis)
		})

		idh := handlers.NewIdentityHandler(s.store, s.identitySyncer)
		r.Route("/identity", func(r chi.Router) {
			r.Get("/status", idh.Status)
			r.Post("/sync", idh.Sync)
			r.Get("/users", idh.List)
			r.Post("/users", idh.Create)
			r.Get("/users/{sam}", idh.Get)
			r.Delete("/users/{sam}", idh.Delete)
		})

		rvh := handlers.NewRuleVersionHandler(s.store)
		r.Route("/rule-versions", func(r chi.Router) {
			r.Get("/", rvh.ListFiles)
			r.Get("/history", rvh.ListVersions)
			r.Get("/content", rvh.GetVersion)
			r.Post("/", rvh.SaveVersion)
			r.Get("/diff", rvh.Diff)
			r.Post("/validate", rvh.Validate)
		})

		pbh := handlers.NewPlaybookHandler(s.store)
		r.Route("/playbooks", func(r chi.Router) {
			r.Get("/", pbh.List)
			r.Post("/", pbh.Create)
			r.Get("/{id}", pbh.Get)
			r.Put("/{id}", pbh.Update)
			r.Delete("/{id}", pbh.Delete)
			r.Get("/{id}/executions", pbh.ListExecutions)
		})
		r.Get("/playbook-executions", pbh.AllExecutions)

		soch := handlers.NewSOCHandler(s.store)
		csh := handlers.NewCaseHandler(s.store, s.casesCfg, s.caseNotifier)
		csh.SetAssigner(s.caseAssigner)
		r.Route("/cases", func(r chi.Router) {
			r.Get("/", csh.List)
			r.Post("/", csh.Create)
			// Static sub-paths must precede /{id} so they aren't captured as an id.
			r.Get("/metrics", soch.Metrics)
			r.Get("/fp-stats", soch.FPStats)
			r.Get("/{id}", csh.Get)
			r.Put("/{id}", csh.Update)
			r.Delete("/{id}", csh.Delete)
			r.Get("/{id}/notes", csh.ListNotes)
			r.Post("/{id}/notes", csh.AddNote)
			r.Get("/{id}/evidence", csh.ListEvidence)
			r.Post("/{id}/evidence", csh.AddEvidence)
			r.Get("/{id}/history", csh.ListHistory)
		})

		// SOC workflow roster/schedule (metrics + fp-stats are under /cases above).
		r.Route("/soc", func(r chi.Router) {
			r.Get("/engineers", soch.ListEngineers)
			r.Post("/engineers", soch.UpsertEngineer)
			r.Delete("/engineers/{sam}", soch.DeleteEngineer)
			r.Get("/shifts", soch.ListShifts)
			r.Post("/shifts", soch.AddShift)
			r.Delete("/shifts/{id}", soch.DeleteShift)
		})
	})

	return r
}
