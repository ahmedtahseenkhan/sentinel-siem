package opensearch

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/watchvault/watchvault/internal/config"
	"go.uber.org/zap"
)

type Client struct {
	os     *opensearch.Client
	logger *zap.Logger
	cfg    config.OpenSearchConfig
}

func NewClient(cfg config.OpenSearchConfig, logger *zap.Logger) (*Client, error) {
	// Properly tuned transport — reuses connections across bulk requests.
	// Default net/http transport has MaxIdleConnsPerHost=2 which is too low
	// for high-throughput SIEM bulk indexing.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
	}

	osCfg := opensearch.Config{
		Addresses:             cfg.Addresses,
		Username:              cfg.Username,
		Password:              cfg.Password,
		Transport:             transport,
		RetryOnStatus:         []int{502, 503, 504, 429},
		MaxRetries:            3,
		EnableRetryOnTimeout:  true,
	}

	client, err := opensearch.NewClient(osCfg)
	if err != nil {
		return nil, fmt.Errorf("create opensearch client: %w", err)
	}

	return &Client{os: client, logger: logger, cfg: cfg}, nil
}

func (c *Client) Ping() error {
	res, err := c.os.Info()
	if err != nil {
		return fmt.Errorf("opensearch ping: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("opensearch error: %s", res.String())
	}
	c.logger.Info("opensearch connected", zap.String("status", res.Status()))
	return nil
}

func (c *Client) Raw() *opensearch.Client {
	return c.os
}
