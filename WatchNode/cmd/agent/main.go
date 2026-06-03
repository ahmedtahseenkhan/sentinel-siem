package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/collectors/audit"
	"github.com/watchnode/watchnode/internal/collectors/canary"
	"github.com/watchnode/watchnode/internal/collectors/cloud"
	"github.com/watchnode/watchnode/internal/collectors/docker"
	"github.com/watchnode/watchnode/internal/collectors/fim"
	"github.com/watchnode/watchnode/internal/collectors/logs"
	"github.com/watchnode/watchnode/internal/collectors/network"
	"github.com/watchnode/watchnode/internal/collectors/osquery"
	"github.com/watchnode/watchnode/internal/collectors/process"
	"github.com/watchnode/watchnode/internal/collectors/registry"
	"github.com/watchnode/watchnode/internal/collectors/rootcheck"
	"github.com/watchnode/watchnode/internal/collectors/sca"
	"github.com/watchnode/watchnode/internal/collectors/syscollector"
	"github.com/watchnode/watchnode/internal/collectors/system"
	"github.com/watchnode/watchnode/internal/collectors/vulnerability"
	"github.com/watchnode/watchnode/internal/collectors/yarascan"
	"github.com/watchnode/watchnode/internal/communication"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/internal/updater"
	"go.uber.org/zap"
)

// Version is the current agent version.  Overridden at build time via ldflags:
//
//	go build -ldflags "-X main.Version=1.2.3"
const Version = "0.1.0"

func main() {
	configPath := flag.String("config", "", "Path to config file")
	install := flag.Bool("install", false, "Install as system service")
	uninstall := flag.Bool("uninstall", false, "Uninstall service")
	flag.Parse()

	if *uninstall {
		if err := agent.ServiceUninstall(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled")
		return
	}

	if *install {
		binary, _ := os.Executable()
		cfgPath := *configPath
		if cfgPath == "" {
			cfgPath = "/etc/watchnode/agent/config.yaml"
		}
		if err := agent.ServiceInstall(binary, cfgPath, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Service installed")
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	log, err := agent.NewLogger("info")
	if err != nil {
		log = agent.NewLoggerDevelopment()
	}

	// runAgent is the platform-agnostic agent loop used both for CLI and service modes.
	runAgent := func(ctx context.Context) {
		comm := communication.NewClient(cfg)
		a, err := agent.New(cfg, log, comm)
		if err != nil {
			log.Error("create agent", zap.Error(err))
			return
		}

		collectors := buildCollectors(cfg)
		a.SetCollectors(collectors)

		if err := a.Start(ctx); err != nil {
			log.Error("start agent", zap.Error(err))
			return
		}

		// Config integrity monitoring — alerts the SOC if config.yaml is
		// tampered with while the agent is running.
		if *configPath != "" {
			checker, err := agent.NewConfigIntegrityChecker(*configPath, "", log)
			if err != nil {
				log.Warn("config integrity check failed to init", zap.Error(err))
			} else {
				stopCh := ctx.Done()
				go checker.RunPeriodicCheck(stopCh, func(path, expected, current string) {
					log.Warn("CONFIG TAMPER DETECTED",
						zap.String("path", path),
						zap.String("expected_sha256", expected),
						zap.String("current_sha256", current),
					)
				})
			}
		}

		if cfg.AutoUpdate.Enabled {
			uCfg := updater.Config{
				Enabled:         cfg.AutoUpdate.Enabled,
				UpdateServerURL: cfg.AutoUpdate.UpdateServerURL,
				CheckInterval:   cfg.AutoUpdate.CheckInterval,
				AllowPrerelease: cfg.AutoUpdate.AllowPrerelease,
			}
			var zapLog *zap.Logger
			if zl, ok := log.(*agent.ZapLogger); ok {
				zapLog = zl.Logger
			} else {
				zapLog, _ = zap.NewProduction()
			}
			u := updater.New(uCfg, Version, zapLog)
			go u.Start(ctx)
		}

		<-ctx.Done()
		a.Stop()
	}

	// When started by the Windows SCM, hand control to the service runner.
	// It receives START/STOP signals from SCM and translates them to context cancellation.
	// On exit with non-zero code the SCM triggers the configured failure/restart actions.
	if isRunningAsService() {
		if err := runAsService(runAgent); err != nil {
			fmt.Fprintf(os.Stderr, "service run: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal CLI mode: run until SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	runAgent(ctx)
}

func loadConfig(path string) (*agent.Config, error) {
	if path != "" {
		return agent.LoadConfig(path)
	}
	for _, p := range agent.ConfigPaths() {
		cfg, err := agent.LoadConfig(p)
		if err == nil {
			return cfg, nil
		}
	}
	return agent.DefaultConfig(), nil
}

func buildCollectors(cfg *agent.Config) []models.Collector {
	var collectors []models.Collector
	if cfg.Collectors.System.Enabled {
		collectors = append(collectors, system.New(cfg.Collectors.System))
	}
	if cfg.Collectors.Process.Enabled {
		collectors = append(collectors, process.New(cfg.Collectors.Process))
	}
	if cfg.Collectors.Network.Enabled {
		collectors = append(collectors, network.New(cfg.Collectors.Network))
	}
	if cfg.Collectors.FileIntegrity.Enabled {
		collectors = append(collectors, fim.New(cfg.Collectors.FileIntegrity))
	}
	if cfg.Collectors.Logs.Enabled {
		collectors = append(collectors, logs.New(cfg.Collectors.Logs))
	}
	if cfg.Collectors.SCA.Enabled {
		collectors = append(collectors, sca.New(cfg.Collectors.SCA))
	}
	if cfg.Collectors.Rootcheck.Enabled {
		collectors = append(collectors, rootcheck.New(cfg.Collectors.Rootcheck))
	}
	if cfg.Collectors.Docker.Enabled {
		collectors = append(collectors, docker.New(cfg.Collectors.Docker))
	}
	if cfg.Collectors.Syscollector.Enabled {
		collectors = append(collectors, syscollector.New(cfg.Collectors.Syscollector))
	}
	if cfg.Collectors.Registry.Enabled {
		collectors = append(collectors, registry.New(cfg.Collectors.Registry))
	}
	if cfg.Collectors.Osquery.Enabled {
		collectors = append(collectors, osquery.New(cfg.Collectors.Osquery))
	}
	if cfg.Collectors.Canary.Enabled {
		collectors = append(collectors, canary.New(cfg.Collectors.Canary))
	}
	if cfg.Collectors.Yara.Enabled {
		collectors = append(collectors, yarascan.New(cfg.Collectors.Yara))
	}
	if cfg.Collectors.Vulnerability.Enabled {
		collectors = append(collectors, vulnerability.New(cfg.Collectors.Vulnerability))
	}
	if cfg.Collectors.Cloud.Enabled {
		collectors = append(collectors, cloud.New(cfg.Collectors.Cloud))
	}
	if cfg.Collectors.Audit.Enabled {
		collectors = append(collectors, audit.New(cfg.Collectors.Audit))
	}
	return collectors
}
