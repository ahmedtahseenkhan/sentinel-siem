package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	OpenSearch OpenSearchConfig `yaml:"opensearch"`
	Pipeline   PipelineConfig   `yaml:"pipeline"`
	Indices    IndicesConfig    `yaml:"indices"`
	Logging    LoggingConfig    `yaml:"logging"`
	Kafka      KafkaConfig      `yaml:"kafka"`
}

type KafkaConfig struct {
	Brokers       []string `yaml:"brokers"`        // e.g. ["kafka:9092"]
	ConsumerGroup string   `yaml:"consumer_group"` // default: sentinel-watchvault
}

type ServerConfig struct {
	GRPC GRPCConfig `yaml:"grpc"`
	API  APIConfig  `yaml:"api"`
}

type GRPCConfig struct {
	ListenAddress string    `yaml:"listen_address"`
	TLS           TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

type APIConfig struct {
	ListenAddress string          `yaml:"listen_address"`
	Auth          AuthConfig      `yaml:"auth"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig controls per-IP token-bucket rate limiting on the HTTP API.
type RateLimitConfig struct {
	RPS   int `yaml:"rps"`   // requests per second per IP; 0 = disabled
	Burst int `yaml:"burst"` // burst capacity; defaults to 2×RPS when 0
}

type AuthConfig struct {
	APIKey string `yaml:"api_key"`
}

type OpenSearchConfig struct {
	Addresses          []string `yaml:"addresses"`
	Username           string   `yaml:"username"`
	Password           string   `yaml:"password"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	CACert             string   `yaml:"ca_cert"`
}

type PipelineConfig struct {
	Workers       int    `yaml:"workers"`
	BufferSize    int    `yaml:"buffer_size"`
	FlushInterval string `yaml:"flush_interval"`
	BulkSize      int    `yaml:"bulk_size"`
}

type IndicesConfig struct {
	Prefix        string `yaml:"prefix"`
	Rollover      string `yaml:"rollover"`
	RetentionDays int    `yaml:"retention_days"`
	Shards        int    `yaml:"shards"`
	Replicas      int    `yaml:"replicas"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	ApplyEnvOverrides(&cfg)
	return &cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			GRPC: GRPCConfig{ListenAddress: "0.0.0.0:50052"},
			API:  APIConfig{ListenAddress: "0.0.0.0:9500"},
		},
		OpenSearch: OpenSearchConfig{
			Addresses: []string{"https://localhost:9200"},
			Username:  "admin",
			Password:  "admin",
		},
		Pipeline: PipelineConfig{
			Workers:       4,
			BufferSize:    10000,
			FlushInterval: "5s",
			BulkSize:      500,
		},
		Indices: IndicesConfig{
			Prefix:        "watchvault",
			Rollover:      "daily",
			RetentionDays: 90,
			Shards:        1,
			Replicas:      1,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

func SearchPaths() []string {
	return []string{
		"/etc/watchvault/config.yaml",
		os.Getenv("HOME") + "/.watchvault/config.yaml",
		"./config.yaml",
	}
}

func ApplyEnvOverrides(cfg *Config) {
	if v := os.Getenv("WATCHVAULT_GRPC_LISTEN"); v != "" {
		cfg.Server.GRPC.ListenAddress = v
	}
	if v := os.Getenv("WATCHVAULT_API_LISTEN"); v != "" {
		cfg.Server.API.ListenAddress = v
	}
	if v := os.Getenv("WATCHVAULT_API_KEY"); v != "" {
		cfg.Server.API.Auth.APIKey = v
	}
	// WATCHVAULT_OPENSEARCH_URLS accepts comma-separated addresses for cluster mode.
	// Falls back to WATCHVAULT_OPENSEARCH_URL for single-node compatibility.
	if v := os.Getenv("WATCHVAULT_OPENSEARCH_URLS"); v != "" {
		var addrs []string
		for _, a := range strings.Split(v, ",") {
			if s := strings.TrimSpace(a); s != "" {
				addrs = append(addrs, s)
			}
		}
		if len(addrs) > 0 {
			cfg.OpenSearch.Addresses = addrs
		}
	} else if v := os.Getenv("WATCHVAULT_OPENSEARCH_URL"); v != "" {
		cfg.OpenSearch.Addresses = []string{v}
	}
	if v := os.Getenv("WATCHVAULT_OPENSEARCH_USER"); v != "" {
		cfg.OpenSearch.Username = v
	}
	if v := os.Getenv("WATCHVAULT_OPENSEARCH_PASS"); v != "" {
		cfg.OpenSearch.Password = v
	}
	if v := os.Getenv("WATCHVAULT_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("WATCHVAULT_KAFKA_BROKERS"); v != "" {
		for _, b := range strings.Split(v, ",") {
			if s := strings.TrimSpace(b); s != "" {
				cfg.Kafka.Brokers = append(cfg.Kafka.Brokers, s)
			}
		}
	}
	if v := os.Getenv("WATCHVAULT_KAFKA_GROUP"); v != "" {
		cfg.Kafka.ConsumerGroup = v
	}
}
