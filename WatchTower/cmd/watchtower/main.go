package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/watchtower/watchtower/internal/aitriage"
	"github.com/watchtower/watchtower/internal/assign"
	"github.com/watchtower/watchtower/internal/audit"
	"github.com/watchtower/watchtower/internal/casegen"
	"github.com/watchtower/watchtower/internal/casesla"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/license"
	"github.com/watchtower/watchtower/internal/engine"
	"github.com/watchtower/watchtower/internal/engine/decoder"
	"github.com/watchtower/watchtower/internal/forwarder"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/response"
	"github.com/watchtower/watchtower/internal/server/api"
	"github.com/watchtower/watchtower/internal/identity"
	"github.com/watchtower/watchtower/internal/enrich"
	"github.com/watchtower/watchtower/internal/notifier"
	"github.com/watchtower/watchtower/internal/playbook"
	"github.com/watchtower/watchtower/internal/rba"
	"github.com/watchtower/watchtower/internal/ueba"
	grpcserver "github.com/watchtower/watchtower/internal/server/grpc"
	syslogserver "github.com/watchtower/watchtower/internal/server/syslog"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/internal/threatintel"
	"github.com/watchtower/watchtower/internal/vuln"
	"go.uber.org/zap"
)

const Version = "0.1.0"

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := initLogger(cfg.Logging)
	defer logger.Sync()

	logger.Info("WatchTower Manager starting",
		zap.String("version", Version),
		zap.String("grpc_listen", cfg.Server.GRPC.ListenAddress),
		zap.String("api_listen", cfg.Server.API.ListenAddress),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// License verification
	if cfg.License.Token != "" {
		pubKey, err := license.LoadPublicKeyFile(cfg.License.PublicKey)
		if err != nil {
			logger.Fatal("license: cannot load public key", zap.Error(err))
		}
		lic, err := license.Verify(cfg.License.Token, pubKey)
		if err != nil {
			logger.Fatal("license verification failed", zap.Error(err))
		}
		logger.Info("license verified",
			zap.String("customer", lic.CustomerID),
			zap.Time("expires", time.Unix(lic.ExpiresAt, 0)),
			zap.Int("max_agents", lic.MaxAgents),
			zap.Strings("features", lic.Features),
		)
	} else {
		logger.Warn("no license configured — running in community mode (unlimited agents, core features only)")
	}

	// Store
	if cfg.Store.DatabaseURL == "" {
		logger.Fatal("WATCHTOWER_DATABASE_URL is required — set a PostgreSQL connection string")
	}
	st, err := store.New(cfg.Store.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to open store", zap.Error(err))
	}
	defer st.Close()
	logger.Info("store connected", zap.String("driver", "postgresql"))

	// Seed rule files into version store (idempotent — skips if already versioned)
	go seedRuleVersions(cfg.Engine.RulesDir, st, logger)

	// Ensure monthly alert partitions exist (startup + background refresh)
	if err := st.EnsureFuturePartitions(3); err != nil {
		logger.Warn("ensure_future_partitions failed", zap.Error(err))
	}
	go runMaintenanceLoop(ctx, st, logger)

	// Registry + heartbeat monitor
	reg := registry.New(st, logger)
	reg.StartHeartbeatMonitor(registry.DefaultHeartbeatCheckInterval, registry.DefaultHeartbeatTimeout)
	defer reg.Stop()

	// Forwarder
	fwd := forwarder.New(cfg.Forwarder, logger)
	if err := fwd.Start(ctx); err != nil {
		logger.Fatal("failed to start forwarder", zap.Error(err))
	}
	defer fwd.Stop()

	// Audit logger — uses the forwarder to ship records to watchvault-audit index.
	// Hash-chain + HMAC signing enabled when AUDIT_SIGNING_KEY is set; auditors
	// can replay the chain to detect tampering.
	auditKey := []byte(os.Getenv("AUDIT_SIGNING_KEY"))
	if len(auditKey) == 0 {
		logger.Warn("AUDIT_SIGNING_KEY not set — audit records will use hash chain only (no HMAC). Set a 32+ byte secret for tamper-resistant audit.")
	}
	auditLogger := audit.New(fwd, auditKey, logger)

	// Engine
	eng := engine.New(cfg.Engine, logger, fwd, st)
	if err := eng.LoadConfigs(); err != nil {
		logger.Fatal("failed to load engine configs", zap.Error(err))
	}
	respMgr := response.NewManager(logger, reg, st)
	eng.SetResponder(respMgr)

	// Vulnerability scanner
	if cfg.Vuln.Enabled {
		vulnScanner := vuln.NewScanner(logger)
		if err := vulnScanner.LoadDatabase(cfg.Vuln.DBPath); err != nil {
			logger.Warn("failed to load vuln database", zap.Error(err))
		}
		eng.SetVulnChecker(vulnScanner)

		// Periodic feed updates in background.
		go func() {
			updateInterval, err := time.ParseDuration(cfg.Vuln.UpdateInterval)
			if err != nil || updateInterval <= 0 {
				updateInterval = 6 * time.Hour
			}
			ticker := time.NewTicker(updateInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := vulnScanner.UpdateDatabase(cfg.Vuln.DBPath, cfg.Vuln.FeedURL); err != nil {
						logger.Warn("vuln database update failed", zap.Error(err))
					}
				}
			}
		}()
	}

	// SOAR playbook executor — wire CDB manager so add_to_watchlist persists entries
	pbExec := playbook.NewExecutor(st, reg, logger)
	pbExec.SetCDB(eng.CDB())
	pbExec.SetCDBDir(cfg.Engine.CDBDir)
	eng.SetPlaybookHook(pbExec)

	// Risk-Based Alerting engine
	// Auto-assignment engine — routes new cases to on-shift SOC engineers.
	assignEngine := assign.New(st, logger)

	rbaEngine := rba.NewEngine(st, logger)
	rbaEngine.SetAssigner(assignEngine)
	rbaEngine.SetCasesConfig(cfg.Cases)
	eng.SetRBAHook(rbaEngine)

	// AI triage: summarize fired Risk Notables with an LLM and attach the
	// summary to the auto-created case. Runs async off the alert path.
	// Provider "ollama" keeps alert data local (free, self-hosted); "claude"
	// (default) uses the Anthropic API.
	if cfg.AITriage.Enabled {
		timeout := time.Duration(cfg.AITriage.TimeoutSecs) * time.Second
		switch strings.ToLower(cfg.AITriage.Provider) {
		case "ollama":
			triager := aitriage.NewOllamaSummarizer(
				cfg.AITriage.BaseURL, cfg.AITriage.Model, cfg.AITriage.APIKey, timeout, logger)
			rbaEngine.SetTriager(triager)
			logger.Info("ai triage enabled",
				zap.String("provider", "ollama"),
				zap.String("base_url", cfg.AITriage.BaseURL),
				zap.String("model", cfg.AITriage.Model))
		default: // "claude" or empty
			apiKey := cfg.AITriage.APIKey
			if apiKey == "" {
				apiKey = os.Getenv("ANTHROPIC_API_KEY")
			}
			if apiKey == "" {
				logger.Warn("ai_triage (claude) enabled but no API key set (ai_triage.api_key or ANTHROPIC_API_KEY) — disabling")
			} else {
				triager := aitriage.NewSummarizer(apiKey, cfg.AITriage.Model, timeout, logger)
				rbaEngine.SetTriager(triager)
				logger.Info("ai triage enabled",
					zap.String("provider", "claude"),
					zap.String("model", cfg.AITriage.Model))
			}
		}
	}

	// VirusTotal alert enrichment. Synchronous on the alert hot path, but
	// rate-limited + TTL-cached so a busy ruleset can't burn the daily quota.
	if cfg.Enrich.VirusTotal.Enabled && cfg.Enrich.VirusTotal.APIKey != "" {
		vt := enrich.NewVirusTotal(enrich.VTConfig{
			Enabled:      cfg.Enrich.VirusTotal.Enabled,
			APIKey:       cfg.Enrich.VirusTotal.APIKey,
			MinLevel:     cfg.Enrich.VirusTotal.MinLevel,
			CacheTTLSecs: cfg.Enrich.VirusTotal.CacheTTLSecs,
		}, logger)
		eng.SetEnricherHook(vt)
		logger.Info("virustotal enrichment enabled",
			zap.Int("min_level", cfg.Enrich.VirusTotal.MinLevel))
	}

	// Outbound notifier (Slack/Teams/webhook/email). Hoisted so the case
	// ticketing subsystem (auto-create, SLA sweeper, API handler) can reuse it.
	var notif *notifier.Notifier
	if cfg.Notifier.Enabled {
		notif = notifier.New(cfg.Notifier, logger)
		eng.SetNotifierHook(notif)

		// Fire a notification whenever an agent goes disconnected.
		reg.SetDisconnectHook(func(agent *models.Agent) {
			notif.NotifyAgentDisconnect(agent)
		})

		logger.Info("notifier enabled",
			zap.Int("destinations", len(cfg.Notifier.Destinations)),
		)
	}

	// Auto-create cases (native ticketing) from high-severity alerts.
	if cfg.Cases.AutoCreate.Enabled {
		gen := casegen.New(st, cfg.Cases, logger)
		gen.SetAssigner(assignEngine)
		eng.SetCaseHook(gen)
		logger.Info("auto-case generation enabled",
			zap.Int("min_level", cfg.Cases.MinLevelOrDefault()))
	}

	// Case SLA sweeper — flags overdue cases, escalates, and notifies. Runs
	// even without auto-create so manually opened cases still get SLA tracking.
	var slaNotif casesla.Notifier
	if notif != nil {
		slaNotif = notif
	}
	slaSweeper := casesla.New(st, slaNotif, cfg.Cases, logger)
	slaSweeper.SetAssigner(assignEngine) // breach → escalate ownership to a senior tier
	go slaSweeper.Start(ctx)

	eng.Start()
	defer eng.Stop()

	// Wire engine into registry so agent lifecycle events (connect/disconnect/
	// reconnect) are ingested and can match rules 501-509.
	reg.SetEngine(eng)

	// Wire registry as agent resolver so every event and alert gets agent_name
	// (hostname) stamped on it — fixes the blank agent_name gap.
	eng.SetAgentResolver(reg)

	// Threat intel feed manager
	if cfg.ThreatIntel.Enabled {
		tiMgr := threatintel.New(cfg.ThreatIntel, eng.CDB(), logger)
		go tiMgr.Start(ctx)
		logger.Info("threat intel ingestion started",
			zap.Int("sources", len(cfg.ThreatIntel.Sources)),
		)
	}

	// Syslog decoder engine — YAML-driven decoder pipeline.
	syslogDecoderEngine := decoder.NewSyslogEngine(logger)
	syslogDecoderDir := cfg.Engine.DecodersDir + "/syslog"
	if err := syslogDecoderEngine.LoadFromDir(syslogDecoderDir); err != nil {
		logger.Warn("syslog decoder: failed to load built-in decoders",
			zap.String("dir", syslogDecoderDir), zap.Error(err))
	} else {
		logger.Info("syslog decoders loaded",
			zap.String("dir", syslogDecoderDir),
			zap.Int("total", syslogDecoderEngine.Count()))
	}
	syslogDecoderEngine.StartWatcher(ctx)

	// Syslog receiver (UDP + TCP)
	if cfg.Syslog.Enabled {
		addr := cfg.Syslog.Addr
		if addr == "" {
			addr = ":514"
		}
		syslogSrv := syslogserver.New(addr, cfg.Syslog.MaxMessageSize, eng, logger)
		syslogSrv.SetDecoder(syslogDecoderEngine)
		if err := syslogSrv.Start(); err != nil {
			logger.Warn("syslog receiver failed to start", zap.Error(err))
		} else {
			defer syslogSrv.Stop()
		}
	}

	// gRPC server
	grpcHandler := grpcserver.NewHandler(logger, reg, eng, cfg.Server.GRPC.EnrollToken)
	grpcHandler.SetAuditLogger(auditLogger)
	grpcSrv := grpcserver.NewServer(cfg.Server.GRPC, logger, grpcHandler)
	go func() {
		if err := grpcSrv.Start(); err != nil {
			logger.Error("gRPC server exited", zap.Error(err))
		}
	}()

	// Identity (LDAP/AD sync)
	idMgr := identity.NewManager(cfg.Identity, st, logger)
	go idMgr.Start(ctx)

	// UEBA event collector (wired into engine for raw event behavioral analysis)
	uebaCollector := ueba.NewEventCollector()
	eng.SetUebaHook(uebaCollector)

	// UEBA analyzer (runs hourly). Wire the engine as alert emitter so detected
	// anomalies surface as first-class alerts and accrue RBA entity risk.
	uebaAnalyzer := ueba.NewAnalyzer(st, logger, uebaCollector)
	uebaAnalyzer.SetEmitter(eng)
	uebaAnalyzer.SetConfig(cfg.UEBA)
	go uebaAnalyzer.Start(ctx)

	// API server
	apiSrv := api.NewServer(cfg.Server.API, logger, reg, st, eng, auditLogger)
	apiSrv.SetSyslogDecoder(syslogDecoderEngine)
	apiSrv.SetUebaAnalyzer(uebaAnalyzer)
	apiSrv.SetArtifactConfig(cfg.Server.GRPC.EnrollToken, os.Getenv("WATCHTOWER_ARTIFACT_DIR"))
	apiSrv.SetCaseTicketing(cfg.Cases, notif)
	apiSrv.SetCaseAssigner(assignEngine)
	if cfg.Identity.Enabled {
		apiSrv.SetIdentitySyncer(idMgr)
	}
	go func() {
		if err := apiSrv.Start(); err != nil {
			logger.Error("API server exited", zap.Error(err))
		}
	}()

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutdown signal received", zap.String("signal", sig.String()))

	// Graceful shutdown
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	grpcSrv.Stop(10 * time.Second)
	if err := apiSrv.Stop(shutdownCtx); err != nil {
		logger.Error("API server shutdown error", zap.Error(err))
	}

	logger.Info("WatchTower Manager stopped")
}

// seedRuleVersions imports existing rule files into the version store so they
// immediately appear in the versioning UI. Runs once — files already versioned
// are skipped because ListVersionedFiles will show them.
func seedRuleVersions(rulesDir string, st *store.Store, logger *zap.Logger) {
	if rulesDir == "" {
		return
	}
	existing, err := st.ListVersionedFiles()
	if err != nil {
		return
	}
	seeded := make(map[string]bool)
	for _, f := range existing {
		if name, ok := f["rule_file"].(string); ok {
			seeded[name] = true
		}
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		logger.Warn("rule versioning: cannot read rules dir", zap.Error(err))
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		if seeded[entry.Name()] {
			continue
		}
		content, err := os.ReadFile(rulesDir + "/" + entry.Name())
		if err != nil {
			continue
		}
		if _, err := st.SaveRuleVersion(entry.Name(), string(content), "Initial import", "system"); err != nil {
			logger.Warn("rule versioning: seed failed", zap.String("file", entry.Name()), zap.Error(err))
		} else {
			logger.Info("rule versioning: seeded", zap.String("file", entry.Name()))
		}
	}
}

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.LoadConfig(path)
	}
	for _, p := range config.SearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return config.LoadConfig(p)
		}
	}
	cfg := config.DefaultConfig()
	config.ApplyEnvOverrides(cfg)
	return cfg, nil
}

func initLogger(cfg config.LoggingConfig) *zap.Logger {
	var zapCfg zap.Config
	if cfg.Level == "debug" {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}

	if cfg.Output != "" && cfg.Output != "stdout" {
		zapCfg.OutputPaths = []string{cfg.Output, "stdout"}
	}

	switch cfg.Level {
	case "debug":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := zapCfg.Build()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
	return logger
}

// runMaintenanceLoop runs database maintenance tasks on a schedule:
//   - Hourly:  purge expired RBA risk events
//   - Daily:   ensure future alert partitions exist (3 months ahead)
//   - Daily:   archive forwarded alerts older than 90 days
//   - Monthly: drop empty old partitions (older than 6 months)
func runMaintenanceLoop(ctx context.Context, st interface {
	EnsureFuturePartitions(int) error
	ArchiveOldAlerts(int) (int, error)
	PurgeExpiredRbaEvents() (int, error)
	DropEmptyOldPartitions(int) (int, error)
}, logger *zap.Logger) {
	hourly  := time.NewTicker(1 * time.Hour)
	daily   := time.NewTicker(24 * time.Hour)
	monthly := time.NewTicker(30 * 24 * time.Hour)
	defer hourly.Stop()
	defer daily.Stop()
	defer monthly.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-hourly.C:
			if n, err := st.PurgeExpiredRbaEvents(); err != nil {
				logger.Warn("purge_expired_rba_events failed", zap.Error(err))
			} else if n > 0 {
				logger.Info("purged expired RBA risk events", zap.Int("rows", n))
			}

		case <-daily.C:
			if err := st.EnsureFuturePartitions(3); err != nil {
				logger.Warn("ensure_future_partitions failed", zap.Error(err))
			}
			if n, err := st.ArchiveOldAlerts(90); err != nil {
				logger.Warn("archive_old_alerts failed", zap.Error(err))
			} else if n > 0 {
				logger.Info("archived old alerts", zap.Int("rows", n))
			}

		case <-monthly.C:
			if n, err := st.DropEmptyOldPartitions(6); err != nil {
				logger.Warn("drop_empty_old_partitions failed", zap.Error(err))
			} else if n > 0 {
				logger.Info("dropped empty old partitions", zap.Int("partitions", n))
			}
		}
	}
}
