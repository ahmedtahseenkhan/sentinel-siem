package manager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/pkg/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
)

type Server struct {
	cfg   *Config
	log   agent.Logger
	store *Store
	grpc  *grpc.Server
	lis   net.Listener
}

func NewServer(cfg *Config, log agent.Logger, store *Store) *Server {
	return &Server{cfg: cfg, log: log, store: store}
}

func (s *Server) Start() error {
	if s.cfg.Server.ListenAddress == "" {
		s.cfg.Server.ListenAddress = "0.0.0.0:50051"
	}
	lis, err := net.Listen("tcp", s.cfg.Server.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.lis = lis

	tlsCfg, err := s.serverTLSConfig(s.cfg.Server.TLS)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
	)
	proto.RegisterAgentServiceServer(s.grpc, &grpcService{log: s.log, store: s.store})

	s.log.Info("WatchNode manager listening", zap.String("addr", s.cfg.Server.ListenAddress))
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

func (s *Server) serverTLSConfig(t TLSConfig) (*tls.Config, error) {
	certPEM, err := os.ReadFile(t.Cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(t.Key)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(t.CA)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}, nil
}

type grpcService struct {
	proto.UnimplementedAgentServiceServer
	log   agent.Logger
	store *Store
}

func (g *grpcService) Register(ctx context.Context, req *proto.RegistrationRequest) (*proto.RegistrationResponse, error) {
	if req.AgentId == "" {
		return &proto.RegistrationResponse{Accepted: false, Message: "missing agent_id"}, nil
	}
	r := g.store.UpsertAgentFromRegistration(req)
	g.log.Info("agent registered",
		zap.String("agent_id", r.AgentID),
		zap.String("hostname", r.Hostname),
		zap.String("platform", r.Platform),
	)
	return &proto.RegistrationResponse{Accepted: true, Message: "ok", AgentId: r.AgentID}, nil
}

func (g *grpcService) Heartbeat(ctx context.Context, req *proto.HeartbeatRequest) (*proto.HeartbeatResponse, error) {
	if req.AgentId == "" {
		return &proto.HeartbeatResponse{Acknowledged: false, ServerTime: time.Now().UnixNano()}, nil
	}
	g.store.TouchHeartbeat(req.AgentId, req.Status)
	return &proto.HeartbeatResponse{Acknowledged: true, ServerTime: time.Now().UnixNano()}, nil
}

func (g *grpcService) StreamData(stream proto.AgentService_StreamDataServer) error {
	ctx := stream.Context()

	// We don’t know the agent_id until we receive the first batch.
	var agentID string
	var cmdCh <-chan *proto.ManagerCommand

	sendLoopDone := make(chan struct{})
	defer close(sendLoopDone)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch, err := stream.Recv()
		if err != nil {
			return err
		}

		if agentID == "" {
			agentID = batch.AgentId
			if agentID == "" {
				return fmt.Errorf("missing agent_id in stream")
			}
			g.store.TouchHeartbeat(agentID, "streaming")
			cmdCh = g.store.CommandChannel(agentID)

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-sendLoopDone:
						return
					case cmd, ok := <-cmdCh:
						if !ok || cmd == nil {
							return
						}
						_ = stream.Send(cmd)
					}
				}
			}()
		}

		g.store.TouchHeartbeat(agentID, "streaming")
		g.log.Info("batch received",
			zap.String("agent_id", agentID),
			zap.Int("points", len(batch.Points)),
		)
	}
}

