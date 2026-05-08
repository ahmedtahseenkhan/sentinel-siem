package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/watchvault/watchvault/internal/config"
	"github.com/watchvault/watchvault/internal/index"
	"github.com/watchvault/watchvault/internal/opensearch"
	"github.com/watchvault/watchvault/internal/pipeline"
	"github.com/watchvault/watchvault/internal/server/api"
	grpcserver "github.com/watchvault/watchvault/internal/server/grpc"
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

	logger.Info("WatchVault Indexer starting",
		zap.String("version", Version),
		zap.String("grpc_listen", cfg.Server.GRPC.ListenAddress),
		zap.String("api_listen", cfg.Server.API.ListenAddress),
		zap.Strings("opensearch", cfg.OpenSearch.Addresses),
	)

	// OpenSearch client
	osClient, err := opensearch.NewClient(cfg.OpenSearch, logger)
	if err != nil {
		logger.Fatal("failed to create opensearch client", zap.Error(err))
	}
	if err := osClient.Ping(); err != nil {
		logger.Fatal("opensearch unreachable", zap.Error(err))
	}

	// Index templates
	idxMgr := index.NewManager(osClient, cfg.Indices, logger)
	if err := idxMgr.SetupTemplates(); err != nil {
		logger.Fatal("failed to setup index templates", zap.Error(err))
	}
	if err := idxMgr.ApplyISMPolicy(); err != nil {
		// Non-fatal: ISM plugin may not be installed on all OpenSearch distributions.
		logger.Warn("failed to apply ISM lifecycle policy", zap.Error(err))
	}

	// Ingestion pipeline
	pipe := pipeline.New(cfg.Pipeline, cfg.Indices, osClient, logger)
	pipe.Start()

	// gRPC server
	grpcSvc := grpcserver.NewService(logger, pipe, osClient)
	grpcSrv := grpcserver.NewServer(cfg.Server.GRPC, logger, grpcSvc)
	go func() {
		if err := grpcSrv.Start(); err != nil {
			logger.Fatal("grpc server failed", zap.Error(err))
		}
	}()

	// REST API server
	apiSrv := api.NewServer(cfg.Server.API, logger, osClient, pipe)
	go func() {
		if err := apiSrv.Start(); err != nil {
			logger.Fatal("api server failed", zap.Error(err))
		}
	}()

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutdown signal received", zap.String("signal", sig.String()))

	// Graceful shutdown
	const shutdownGrace = 10 * time.Second

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	grpcSrv.Stop(shutdownGrace)
	if err := apiSrv.Stop(shutdownCtx); err != nil {
		logger.Error("api server shutdown error", zap.Error(err))
	}
	pipe.Stop()

	logger.Info("WatchVault Indexer stopped")
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
	
	// Create default config and apply env overrides if no file is found
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
		panic("failed to init logger: " + err.Error())
	}
	return logger
}
