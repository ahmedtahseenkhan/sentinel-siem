package forwarder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	cfg    config.WatchVaultConfig
	logger *zap.Logger
	conn   *grpc.ClientConn
}

func NewClient(cfg config.WatchVaultConfig, logger *zap.Logger) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("watchvault address not configured")
	}
	if cfg.TLS.Cert == "" || cfg.TLS.Key == "" || cfg.TLS.CA == "" {
		return nil, fmt.Errorf("watchvault tls requires cert, key, and ca")
	}

	tlsCfg, err := loadTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("watchvault tls: %w", err)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial watchvault: %w", err)
	}

	return &Client{cfg: cfg, logger: logger, conn: conn}, nil
}

func loadTLSConfig(t config.TLSConfig) (*tls.Config, error) {
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
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (c *Client) SendEvents(events []*models.Event) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := proto.NewIndexerServiceClient(c.conn)
	stream, err := cli.IngestEvents(ctx)
	if err != nil {
		return fmt.Errorf("ingest events stream: %w", err)
	}

	pbEvents := make([]*proto.IndexEvent, 0, len(events))
	for _, e := range events {
		data, err := json.Marshal(e.Fields)
		if err != nil {
			return fmt.Errorf("marshal event fields: %w", err)
		}
		tags := e.Tags
		if tags == nil {
			tags = map[string]string{}
		}
		pbEvents = append(pbEvents, &proto.IndexEvent{
			Id:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.Type,
			AgentId:   e.AgentID,
			AgentName: e.AgentName,
			Data:      data,
			Tags:      tags,
		})
	}

	batch := &proto.EventBatch{
		Events:         pbEvents,
		SourceManager:  "watchtower",
	}
	if err := stream.Send(batch); err != nil {
		return fmt.Errorf("send event batch: %w", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("close ingest events: %w", err)
	}
	c.logger.Debug("watchvault ingest events",
		zap.Int64("accepted", resp.GetAccepted()),
		zap.Int64("failed", resp.GetFailed()),
	)
	return nil
}

func (c *Client) SendAlerts(alerts []*models.Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := proto.NewIndexerServiceClient(c.conn)
	stream, err := cli.IngestAlerts(ctx)
	if err != nil {
		return fmt.Errorf("ingest alerts stream: %w", err)
	}

	pbAlerts := make([]*proto.IndexAlert, 0, len(alerts))
	for _, a := range alerts {
		id := fmt.Sprintf("%d", a.ID)
		pbAlerts = append(pbAlerts, &proto.IndexAlert{
			Id:               id,
			Timestamp:        a.Timestamp,
			RuleId:           int32(a.RuleID),
			RuleLevel:        int32(a.Level),
			RuleDescription:  a.Description,
			RuleGroups:       a.RuleGroups,
			AgentId:          a.AgentID,
			Title:            a.Title,
			EventData:        []byte(a.EventData),
		})
	}

	if err := stream.Send(&proto.AlertBatch{Alerts: pbAlerts}); err != nil {
		return fmt.Errorf("send alert batch: %w", err)
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("close ingest alerts: %w", err)
	}
	c.logger.Debug("watchvault ingest alerts",
		zap.Int64("accepted", resp.GetAccepted()),
		zap.Int64("failed", resp.GetFailed()),
	)
	return nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
