package api

import (
	"context"
	"net/http"
	"time"

	"github.com/watchtower/watchtower/internal/audit"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine"
	"github.com/watchtower/watchtower/internal/engine/decoder"
	"github.com/watchtower/watchtower/internal/notifier"
	"github.com/watchtower/watchtower/internal/registry"
	"github.com/watchtower/watchtower/internal/server/api/handlers"
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
	syslogDecoder  *decoder.SyslogEngine
	audit          *audit.Logger
	identitySyncer IdentitySyncer
	uebaAnalyzer   UebaRunner
	casesCfg       config.CasesConfig
	caseNotifier   handlers.CaseNotifier
	caseAssigner   handlers.CaseAssigner
	http           *http.Server
	enrollToken    string
	artifactDir    string
}

// SetArtifactConfig wires the enroll token (used to authenticate agent artifact
// uploads — agents hold the enroll token but not the API key) and the directory
// where uploaded forensic bundles are stored.
func (s *Server) SetArtifactConfig(enrollToken, dir string) {
	s.enrollToken = enrollToken
	if dir == "" {
		dir = "/var/lib/watchtower/artifacts"
	}
	s.artifactDir = dir
}

// SetCaseTicketing wires the case SLA config and (optional) notifier into the
// API server so the case handler can stamp due dates and announce changes.
// A nil notifier leaves notifications disabled.
// SetCaseAssigner wires the auto-assignment engine so the case handler routes
// manually/XDR-created cases. nil leaves cases unassigned.
func (s *Server) SetCaseAssigner(a handlers.CaseAssigner) { s.caseAssigner = a }

func (s *Server) SetCaseTicketing(cfg config.CasesConfig, n *notifier.Notifier) {
	s.casesCfg = cfg
	if n != nil {
		s.caseNotifier = n
	}
}

// SetSyslogDecoder wires the syslog decoder engine into the API server.
func (s *Server) SetSyslogDecoder(e *decoder.SyslogEngine) {
	s.syslogDecoder = e
}

// SyslogDecoder returns the syslog decoder engine (satisfies SyslogDecoderProvider).
func (s *Server) SyslogDecoder() *decoder.SyslogEngine {
	return s.syslogDecoder
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
	// Routes are built in Start(), not here: the SetX wiring (case ticketing,
	// assigner, artifact config, ueba, identity) is applied after NewServer, and
	// the handlers must capture those values rather than the zero/nil defaults.
	s.http = &http.Server{
		Addr:         addr,
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
	s.http.Handler = s.routes() // built now so all SetX wiring is in effect
	s.logger.Info("API server listening", zap.String("addr", s.http.Addr))
	return s.http.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
