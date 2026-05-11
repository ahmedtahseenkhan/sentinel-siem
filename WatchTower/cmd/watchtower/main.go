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

	"github.com/watchtower/watchtower/internal/audit"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/license"
	"github.com/watchtower/watchtower/internal/engine"
	"github.com/watchtower/watchtower/internal/forwarder"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/response"
	"github.com/watchtower/watchtower/internal/server/api"
	"github.com/watchtower/watchtower/internal/identity"
	"github.com/watchtower/watchtower/internal/playbook"
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
	auditLogger := audit.New(fwd, logger)

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

	// SOAR playbook executor
	pbExec := playbook.NewExecutor(st, reg, logger)
	eng.SetPlaybookHook(pbExec)

	eng.Start()
	defer eng.Stop()

	// Threat intel feed manager
	if cfg.ThreatIntel.Enabled {
		tiMgr := threatintel.New(cfg.ThreatIntel, eng.CDB(), logger)
		go tiMgr.Start(ctx)
		logger.Info("threat intel ingestion started",
			zap.Int("sources", len(cfg.ThreatIntel.Sources)),
		)
	}

	// Syslog receiver (UDP + TCP)
	if cfg.Syslog.Enabled {
		addr := cfg.Syslog.Addr
		if addr == "" {
			addr = ":514"
		}
		syslogSrv := syslogserver.New(addr, cfg.Syslog.MaxMessageSize, eng, logger)
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

	// API server
	apiSrv := api.NewServer(cfg.Server.API, logger, reg, st, eng, auditLogger)
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
