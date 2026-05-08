package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/manager"
	"go.uber.org/zap"
)

func main() {
	cfgPath := flag.String("config", "configs/manager.yaml.example", "Manager config path")
	flag.Parse()

	log, err := agent.NewLogger("info")
	if err != nil {
		log = agent.NewLoggerDevelopment()
	}

	cfg, err := manager.LoadConfig(*cfgPath)
	if err != nil {
		log.Warn("failed to load config, using defaults", zap.Error(err))
		cfg = manager.DefaultConfig()
	}

	store := manager.NewStore()
	srv := manager.NewServer(cfg, log, store)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("shutting down manager...")
		srv.Stop(5 * time.Second)
	}()

	if err := srv.Start(); err != nil {
		log.Error("manager exited", zap.Error(err))
		os.Exit(1)
	}
}

