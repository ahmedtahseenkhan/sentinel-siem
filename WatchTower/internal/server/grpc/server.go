package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

type Server struct {
	cfg     config.GRPCConfig
	logger  *zap.Logger
	grpc    *grpc.Server
	lis     net.Listener
	handler *Handler
}

func NewServer(cfg config.GRPCConfig, logger *zap.Logger, handler *Handler) *Server {
	return &Server{cfg: cfg, logger: logger, handler: handler}
}

func (s *Server) Start() error {
	addr := s.cfg.ListenAddress
	if addr == "" {
		addr = "0.0.0.0:50051"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	s.lis = lis

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.ChainUnaryInterceptor(UnaryLoggingInterceptor(s.logger)),
		grpc.ChainStreamInterceptor(StreamCNInterceptor()),
	}

	if s.cfg.TLS.Cert != "" {
		tlsCfg, err := s.loadTLS()
		if err != nil {
			return fmt.Errorf("grpc tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	s.grpc = grpc.NewServer(opts...)
	proto.RegisterAgentServiceServer(s.grpc, s.handler)

	s.logger.Info("gRPC server listening", zap.String("addr", addr))
	return s.grpc.Serve(lis)
}

func (s *Server) Stop(grace time.Duration) {
	if s.grpc == nil {
		return
	}
	ch := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(grace):
		s.grpc.Stop()
	}
}

func (s *Server) loadTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.Cert, s.cfg.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	if s.cfg.TLS.CA != "" {
		caPEM, err := os.ReadFile(s.cfg.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = caPool
	}

	return tlsCfg, nil
}
