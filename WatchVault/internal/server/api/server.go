package api

import (
	"context"
	"net/http"
	"time"

	"github.com/watchvault/watchvault/internal/config"
	"github.com/watchvault/watchvault/internal/opensearch"
	"github.com/watchvault/watchvault/internal/pipeline"
	"go.uber.org/zap"
)

type Server struct {
	cfg      config.APIConfig
	logger   *zap.Logger
	client   *opensearch.Client
	pipeline *pipeline.Pipeline
	http     *http.Server
}

func NewServer(cfg config.APIConfig, logger *zap.Logger, client *opensearch.Client, pipe *pipeline.Pipeline) *Server {
	if cfg.Auth.APIKey == "" {
		logger.Fatal("api_key must be configured; refusing to start without authentication")
	}
	s := &Server{
		cfg:      cfg,
		logger:   logger,
		client:   client,
		pipeline: pipe,
	}
	addr := cfg.ListenAddress
	if addr == "" {
		addr = "0.0.0.0:9500"
	}
	s.http = &http.Server{
		Addr:         addr,
		Handler:      s.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

func (s *Server) Start() error {
	s.logger.Info("WatchVault API server listening", zap.String("addr", s.http.Addr))
	return s.http.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
