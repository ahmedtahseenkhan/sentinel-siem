package communication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
	"github.com/watchnode/watchnode/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

// Client is the gRPC manager client with mTLS and batching.
type Client struct {
	cfg       *agent.Config
	conn      *grpc.ClientConn
	client    proto.AgentServiceClient
	batchSize int
	flush     time.Duration
	mu        sync.Mutex
	onCommand func(commandType string, payload []byte)
}

// NewClient creates a new gRPC client.
func NewClient(cfg *agent.Config) *Client {
	batchSize := cfg.Performance.BatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}
	flush := agent.ParseDuration(cfg.Performance.FlushInterval, 30*time.Second)
	return &Client{
		cfg:       cfg,
		batchSize: batchSize,
		flush:     flush,
	}
}

// SetCommandHandler registers a callback for manager commands received on the stream.
func (c *Client) SetCommandHandler(handler func(commandType string, payload []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onCommand = handler
}

// Connect establishes a connection to the manager with mTLS.
func (c *Client) Connect(ctx context.Context) error {
	useTLS := c.cfg.Manager.TLS.Cert != "" || c.cfg.Manager.TLS.Key != "" || c.cfg.Manager.TLS.CA != ""

	var transport grpc.DialOption
	if useTLS {
		tlsCfg, err := loadTLSConfig(c.cfg.Manager.TLS)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		transport = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	} else {
		// No TLS certs configured — connect insecurely.
		// For production deployments configure manager.tls.cert/key/ca.
		transport = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	opts := []grpc.DialOption{
		transport,
		grpc.WithDefaultCallOptions(grpc.UseCompressor("gzip")),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                60 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	conn, err := grpc.DialContext(ctx, c.cfg.Manager.URL, opts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.client = proto.NewAgentServiceClient(conn)
	c.mu.Unlock()
	return nil
}

// Register registers the agent metadata with the manager.
func (c *Client) Register(ctx context.Context, info *models.AgentInfo) error {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return fmt.Errorf("not connected")
	}
	if info == nil {
		return fmt.Errorf("missing agent info")
	}

	// Build labels map, injecting the enrollment token when configured so the
	// manager can authenticate this agent during the registration handshake.
	labels := info.Labels
	if c.cfg.Manager.EnrollToken != "" {
		labels = make(map[string]string, len(info.Labels)+1)
		for k, v := range info.Labels {
			labels[k] = v
		}
		labels["_enroll_token"] = c.cfg.Manager.EnrollToken
	}

	req := &proto.RegistrationRequest{
		AgentId:  info.ID,
		Hostname: info.Hostname,
		Os:       info.OS,
		Platform: info.Platform,
		Version:  info.Version,
		Labels:   labels,
	}

	resp, err := client.Register(ctx, req)
	if err != nil {
		return err
	}
	if resp != nil && !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}
	return nil
}

func loadTLSConfig(t agent.TLSConfig) (*tls.Config, error) {
	if t.Cert == "" || t.Key == "" || t.CA == "" {
		return nil, fmt.Errorf("tls requires cert, key, and ca")
	}
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
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("parse ca cert")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, nil
}

// SendBatch sends a batch of data points to the manager (used by RunStream).
func (c *Client) SendBatch(ctx context.Context, agentID string, points []models.DataPoint) error {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return fmt.Errorf("not connected")
	}
	stream, err := client.StreamData(ctx)
	if err != nil {
		return err
	}
	protoPoints := make([]*proto.DataPoint, 0, len(points))
	for _, p := range points {
		protoPoints = append(protoPoints, DataPointToProto(p))
	}
	batch := &proto.DataBatch{
		AgentId:   agentID,
		Points:    protoPoints,
		Timestamp: time.Now().UnixNano(),
	}
	return stream.Send(batch)
}

// RunStream runs the bidirectional stream: batches points from dataCh and sends them; receives commands.
// Reconnects with exponential backoff on failure.
func (c *Client) RunStream(ctx context.Context, agentID string, dataCh <-chan models.DataPoint) error {
	initialBackoff := agent.ParseDuration(c.cfg.Manager.Reconnect.InitialBackoff, time.Second)
	maxBackoff := agent.ParseDuration(c.cfg.Manager.Reconnect.MaxBackoff, 5*time.Minute)
	backoff := initialBackoff
	for {
		c.mu.Lock()
		client := c.client
		c.mu.Unlock()
		if client == nil {
			return nil
		}
		stream, err := client.StreamData(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				time.Sleep(backoff)
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			}
		}
		backoff = initialBackoff
		done := make(chan struct{})
		go func() {
			for {
				cmd, err := stream.Recv()
				if err != nil {
					close(done)
					return
				}
				if cmd == nil {
					continue
				}
				c.mu.Lock()
				handler := c.onCommand
				c.mu.Unlock()
				if handler != nil {
					payloadCopy := make([]byte, len(cmd.Payload))
					copy(payloadCopy, cmd.Payload)
					handler(cmd.CommandType, payloadCopy)
				}
			}
		}()
		batch := make([]models.DataPoint, 0, c.batchSize)
		flushTimer := time.NewTicker(c.flush)
		sendBatch := func() {
			if len(batch) == 0 {
				return
			}
			pts := make([]*proto.DataPoint, len(batch))
			for i, p := range batch {
				pts[i] = DataPointToProto(p)
			}
			_ = stream.Send(&proto.DataBatch{
				AgentId:   agentID,
				Points:    pts,
				Timestamp: time.Now().UnixNano(),
			})
			batch = batch[:0]
		}
		streamOK := true
		for streamOK {
			select {
			case <-ctx.Done():
				sendBatch()
				flushTimer.Stop()
				return ctx.Err()
			case <-done:
				sendBatch()
				flushTimer.Stop()
				streamOK = false
				break
			case p, ok := <-dataCh:
				if !ok {
					sendBatch()
					flushTimer.Stop()
					return nil
				}
				batch = append(batch, p)
				if len(batch) >= c.batchSize {
					sendBatch()
				}
			case <-flushTimer.C:
				sendBatch()
			}
		}
	}
}

// RunHeartbeat sends heartbeats at the given interval.
func (c *Client) RunHeartbeat(ctx context.Context, agentID string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			client := c.client
			c.mu.Unlock()
			if client == nil {
				continue
			}
			_, _ = client.Heartbeat(ctx, &proto.HeartbeatRequest{
				AgentId:  agentID,
				Timestamp: time.Now().UnixNano(),
				Status:   "running",
			})
		}
	}
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		return err
	}
	return nil
}
