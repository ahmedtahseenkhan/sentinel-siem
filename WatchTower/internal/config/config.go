package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Engine      EngineConfig      `yaml:"engine"`
	Vuln        VulnConfig        `yaml:"vulnerability"`
	Forwarder   ForwarderConfig   `yaml:"forwarder"`
	Store       StoreConfig       `yaml:"store"`
	Logging     LoggingConfig     `yaml:"logging"`
	License     LicenseConfig     `yaml:"license"`
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`
	Syslog      SyslogConfig      `yaml:"syslog"`
	Identity    IdentityConfig    `yaml:"identity"`
}

// IdentityConfig configures LDAP/AD user synchronisation.
type IdentityConfig struct {
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`           // e.g. ldap://dc.company.com:389
	BindDN       string `yaml:"bind_dn"`       // e.g. CN=sentinel,CN=Users,DC=company,DC=com
	BindPassword string `yaml:"bind_password"`
	BaseDN       string `yaml:"base_dn"`       // e.g. DC=company,DC=com
	SyncInterval string `yaml:"sync_interval"` // e.g. "1h"
	UserFilter   string `yaml:"user_filter"`   // default: (objectClass=person)
}

// SyslogConfig enables the built-in UDP/TCP syslog receiver.
// Firewalls, routers, and switches can send RFC 3164/5424 messages directly.
type SyslogConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Addr           string `yaml:"addr"`             // e.g. ":514" or "0.0.0.0:5140"
	MaxMessageSize int    `yaml:"max_message_size"` // bytes, default 64KB
}

type ServerConfig struct {
	GRPC GRPCConfig `yaml:"grpc"`
	API  APIConfig  `yaml:"api"`
}

type GRPCConfig struct {
	ListenAddress string    `yaml:"listen_address"`
	TLS           TLSConfig `yaml:"tls"`
	EnrollToken   string    `yaml:"enroll_token"`
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

type EngineConfig struct {
	RulesDir        string `yaml:"rules_dir"`
	DecodersDir     string `yaml:"decoders_dir"`
	CDBDir          string `yaml:"cdb_dir"`
	Workers         int    `yaml:"workers"`
	DedupWindowSecs int    `yaml:"dedup_window_secs"`
}

type VulnConfig struct {
	Enabled        bool   `yaml:"enabled"`
	DBPath         string `yaml:"db_path"`
	UpdateInterval string `yaml:"update_interval"`
	FeedURL        string `yaml:"feed_url"`
}

type ForwarderConfig struct {
	WatchVault WatchVaultConfig `yaml:"watchvault"`
	Kafka      KafkaConfig      `yaml:"kafka"`
}

type KafkaConfig struct {
	Brokers []string `yaml:"brokers"` // e.g. ["kafka:9092"]
}

type WatchVaultConfig struct {
	Address       string    `yaml:"address"`
	TLS           TLSConfig `yaml:"tls"`
	BatchSize     int       `yaml:"batch_size"`
	FlushInterval string    `yaml:"flush_interval"`
}

type StoreConfig struct {
	Path        string `yaml:"path"`         // legacy SQLite path (ignored when DatabaseURL is set)
	DatabaseURL string `yaml:"database_url"` // PostgreSQL DSN e.g. postgres://user:pass@host:5432/db
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

// LicenseConfig controls RSA-signed license verification.
type LicenseConfig struct {
	Token     string `yaml:"token"`      // base64url license token
	PublicKey string `yaml:"public_key"` // path to PEM-encoded RSA public key
}

// ThreatIntelConfig controls automatic IOC feed ingestion.
type ThreatIntelConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Interval string         `yaml:"interval"` // e.g. "6h"
	Sources  []SourceConfig `yaml:"sources"`
}

// SourceConfig defines a single threat intel feed source.
type SourceConfig struct {
	Type     string `yaml:"type"`      // abuseipdb | otx | plaintext
	URL      string `yaml:"url"`       // override default endpoint
	APIKey   string `yaml:"api_key"`   // authentication key
	ListName string `yaml:"list_name"` // target CDB list name
	Value    string `yaml:"value"`     // value stored per entry (default: malicious)
	Enabled  bool   `yaml:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			GRPC: GRPCConfig{
				ListenAddress: ":50051",
			},
			API: APIConfig{
				ListenAddress: ":9400",
			},
		},
		Engine: EngineConfig{
			RulesDir:    "/etc/watchtower/rules",
			DecodersDir: "/etc/watchtower/decoders",
			CDBDir:      "/etc/watchtower/cdb",
			Workers:     4,
		},
		Vuln: VulnConfig{
			Enabled:        false,
			DBPath:         "/var/lib/watchtower/vuln.db",
			UpdateInterval: "6h",
			FeedURL:        "https://feeds.watchtower.local/cve",
		},
		Forwarder: ForwarderConfig{
			WatchVault: WatchVaultConfig{
				Address:       "localhost:50052",
				BatchSize:     500,
				FlushInterval: "5s",
			},
		},
		Store: StoreConfig{
			Path: "/var/lib/watchtower/state.db",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Output: "stdout",
		},
	}
}

func SearchPaths() []string {
	return []string{
		"/etc/watchtower/config.yaml",
		os.ExpandEnv("$HOME/.watchtower/config.yaml"),
		"./config.yaml",
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// ApplyEnvOverrides overlays environment variables on an existing config.
func ApplyEnvOverrides(cfg *Config) {
	applyEnvOverrides(cfg)
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("WATCHTOWER_GRPC_LISTEN"); v != "" {
		cfg.Server.GRPC.ListenAddress = v
	}
	if v := os.Getenv("WATCHTOWER_API_LISTEN"); v != "" {
		cfg.Server.API.ListenAddress = v
	}
	if v := os.Getenv("WATCHTOWER_API_KEY"); v != "" {
		cfg.Server.API.Auth.APIKey = v
	}
	if v := os.Getenv("WATCHTOWER_STORE_PATH"); v != "" {
		cfg.Store.Path = v
	}
	if v := os.Getenv("WATCHTOWER_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("WATCHTOWER_ENGINE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Engine.Workers = n
		}
	}
	if v := os.Getenv("WATCHTOWER_WATCHVAULT_ADDRESS"); v != "" {
		cfg.Forwarder.WatchVault.Address = v
	}
	if v := os.Getenv("WATCHTOWER_DATABASE_URL"); v != "" {
		cfg.Store.DatabaseURL = v
	}
	if v := os.Getenv("WATCHTOWER_KAFKA_BROKERS"); v != "" {
		for _, b := range strings.Split(v, ",") {
			if s := strings.TrimSpace(b); s != "" {
				cfg.Forwarder.Kafka.Brokers = append(cfg.Forwarder.Kafka.Brokers, s)
			}
		}
	}
	// gRPC server TLS (WatchNode → WatchTower mTLS)
	if v := os.Getenv("WATCHTOWER_GRPC_TLS_CERT"); v != "" {
		cfg.Server.GRPC.TLS.Cert = v
	}
	if v := os.Getenv("WATCHTOWER_GRPC_TLS_KEY"); v != "" {
		cfg.Server.GRPC.TLS.Key = v
	}
	if v := os.Getenv("WATCHTOWER_GRPC_TLS_CA"); v != "" {
		cfg.Server.GRPC.TLS.CA = v
	}
	if v := os.Getenv("WATCHTOWER_SYSLOG_ADDR"); v != "" {
		cfg.Syslog.Enabled = true
		cfg.Syslog.Addr = v
	}
	if v := os.Getenv("WATCHTOWER_LDAP_URL"); v != "" {
		cfg.Identity.Enabled = true
		cfg.Identity.URL = v
	}
	if v := os.Getenv("WATCHTOWER_LDAP_BIND_DN"); v != "" {
		cfg.Identity.BindDN = v
	}
	if v := os.Getenv("WATCHTOWER_LDAP_BIND_PASSWORD"); v != "" {
		cfg.Identity.BindPassword = v
	}
	if v := os.Getenv("WATCHTOWER_LDAP_BASE_DN"); v != "" {
		cfg.Identity.BaseDN = v
	}
}
