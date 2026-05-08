package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/watchvault/watchvault/internal/config"
	pb "github.com/watchvault/watchvault/pkg/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func cnStreamInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := contextWithCN(ss.Context())
		if err := ValidateManagerCN(ctx); err != nil {
			logger.Warn("gRPC stream rejected: CN validation failed",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return err
		}
		wrapped := &cnServerStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

type cnServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *cnServerStream) Context() context.Context { return s.ctx }

type Server struct {
	cfg     config.GRPCConfig
	logger  *zap.Logger
	grpc    *grpc.Server
	svc     *Service
}

func NewServer(cfg config.GRPCConfig, logger *zap.Logger, svc *Service) *Server {
	return &Server{cfg: cfg, logger: logger, svc: svc}
}

func (s *Server) Start() error {
	addr := s.cfg.ListenAddress
	if addr == "" {
		addr = "0.0.0.0:50052"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.ChainStreamInterceptor(cnStreamInterceptor(s.logger)),
	}

	if s.cfg.TLS.Cert != "" || s.cfg.TLS.Key != "" || s.cfg.TLS.CA != "" {
		tlsCfg, err := loadTLSConfig(s.cfg.TLS)
		if err != nil {
			return fmt.Errorf("load grpc tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	s.grpc = grpc.NewServer(opts...)
	pb.RegisterIndexerServiceServer(s.grpc, s.svc)
	s.logger.Info("WatchVault gRPC server listening", zap.String("addr", addr))
	return s.grpc.Serve(lis)
}

func loadTLSConfig(t config.TLSConfig) (*tls.Config, error) {
	if t.Cert == "" || t.Key == "" || t.CA == "" {
		return nil, fmt.Errorf("grpc tls requires cert, key, and ca")
	}

	certPEM, err := os.ReadFile(t.Cert)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(t.Key)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	caPEM, err := os.ReadFile(t.CA)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("parse ca cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
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
