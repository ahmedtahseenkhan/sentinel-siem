package api

import (
	"context"
	"net/http"
	"time"

	"github.com/watchtower/watchtower/internal/audit"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

// IdentitySyncer is satisfied by *identity.Manager (avoids import cycle).
type IdentitySyncer interface {
	Sync() error
}

// UebaRunner is satisfied by *ueba.Analyzer (avoids import cycle).
type UebaRunner interface {
	Analyze()
}

type Server struct {
	cfg            config.APIConfig
	logger         *zap.Logger
	registry       *registry.Registry
	store          *store.Store
	engine         *engine.Engine
	audit          *audit.Logger
	identitySyncer IdentitySyncer
	uebaAnalyzer   UebaRunner
	http           *http.Server
}

func NewServer(cfg config.APIConfig, logger *zap.Logger, reg *registry.Registry, st *store.Store, eng *engine.Engine, al *audit.Logger) *Server {
	if cfg.Auth.APIKey == "" {
		logger.Fatal("api_key must be configured; refusing to start without authentication")
	}
	s := &Server{
		cfg:      cfg,
		logger:   logger,
		registry: reg,
		store:    st,
		engine:   eng,
		audit:    al,
	}
	addr := cfg.ListenAddress
	if addr == "" {
		addr = "0.0.0.0:9400"
	}
	s.http = &http.Server{
		Addr:         addr,
		Handler:      s.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// SetUebaAnalyzer wires the UEBA analyzer into the API server.
func (s *Server) SetUebaAnalyzer(a UebaRunner) {
	s.uebaAnalyzer = a
}

// SetIdentitySyncer wires the LDAP sync manager into the API server.
func (s *Server) SetIdentitySyncer(syncer IdentitySyncer) {
	s.identitySyncer = syncer
}

func (s *Server) Start() error {
	s.logger.Info("API server listening", zap.String("addr", s.http.Addr))
	return s.http.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
