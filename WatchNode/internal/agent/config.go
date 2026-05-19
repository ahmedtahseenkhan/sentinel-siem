package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Agent          AgentConfig          `yaml:"agent"`
	Manager        ManagerConfig        `yaml:"manager"`
	Collectors     CollectorsConfig     `yaml:"collectors"`
	Performance    PerformanceConfig    `yaml:"performance"`
	ActiveResponse ActiveResponseConfig `yaml:"active_response"`
	AutoUpdate     AutoUpdateConfig     `yaml:"autoupdate"`
}

// ActiveResponseConfig controls which manager commands the agent will execute.
type ActiveResponseConfig struct {
	// Enabled must be true for any command to run.
	Enabled bool `yaml:"enabled"`
	// AllowedCommands is a whitelist of command_type values.
	// If empty and Enabled is true, the default builtin set is used.
	AllowedCommands []string `yaml:"allowed_commands"`
	// CommandTimeoutSecs overrides the default per-command timeout.
	CommandTimeoutSecs int `yaml:"command_timeout_secs"`
}

// AutoUpdateConfig controls automatic binary updates.
type AutoUpdateConfig struct {
	// Enabled must be true for update checks to run.
	Enabled bool `yaml:"enabled"`
	// UpdateServerURL is the base URL of the update server.
	// The agent will GET {UpdateServerURL}/watchnode/{os}/{arch}/version.json
	UpdateServerURL string `yaml:"update_server_url"`
	// CheckInterval is a Go duration string (default "24h").
	CheckInterval string `yaml:"check_interval"`
	// AllowPrerelease allows installing pre-release builds.
	AllowPrerelease bool `yaml:"allow_prerelease"`
}

// AgentConfig holds agent identity and labels.
type AgentConfig struct {
	ID     string            `yaml:"id"`
	Name   string            `yaml:"name"`
	Labels map[string]string `yaml:"labels"`
}

// ManagerConfig holds manager connection and TLS settings.
type ManagerConfig struct {
	URL         string          `yaml:"url"`
	TLS         TLSConfig       `yaml:"tls"`
	Reconnect   ReconnectConfig `yaml:"reconnect"`
	EnrollToken string          `yaml:"enroll_token"`
}

// TLSConfig holds mTLS certificate paths.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

// ReconnectConfig holds reconnection backoff settings.
type ReconnectConfig struct {
	MaxAttempts    int    `yaml:"max_attempts"`
	InitialBackoff string `yaml:"initial_backoff"`
	MaxBackoff     string `yaml:"max_backoff"`
}

// CollectorsConfig holds all collector settings.
type CollectorsConfig struct {
	System         SystemCollectorConfig         `yaml:"system"`
	FileIntegrity  FileIntegrityCollectorConfig  `yaml:"file_integrity"`
	Logs           LogsCollectorConfig           `yaml:"logs"`
	Process        ProcessCollectorConfig        `yaml:"process"`
	Network        NetworkCollectorConfig        `yaml:"network"`
	Vulnerability  VulnerabilityCollectorConfig  `yaml:"vulnerability"`
	SCA            SCACollectorConfig            `yaml:"sca"`
	Rootcheck      RootcheckCollectorConfig      `yaml:"rootcheck"`
	Docker         DockerCollectorConfig         `yaml:"docker"`
	Syscollector   SyscollectorConfig            `yaml:"syscollector"`
	Registry       RegistryCollectorConfig       `yaml:"registry"`
	Osquery        OsqueryCollectorConfig        `yaml:"osquery"`
	Cloud          CloudCollectorConfig          `yaml:"cloud"`
}

// CloudCollectorConfig for cloud provider log ingestion.
type CloudCollectorConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Interval string            `yaml:"interval"`
	AWS      AWSCloudConfig    `yaml:"aws"`
	Azure    AzureCloudConfig  `yaml:"azure"`
	GCP      GCPCloudConfig    `yaml:"gcp"`
}

// AWSCloudConfig for AWS CloudTrail and GuardDuty ingestion.
type AWSCloudConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	CloudTrailBucket string `yaml:"cloudtrail_bucket"` // S3 bucket for CloudTrail logs
	GuardDutyRegion  string `yaml:"guardduty_region"`
}

// AzureCloudConfig for Azure Activity Log ingestion.
type AzureCloudConfig struct {
	Enabled        bool   `yaml:"enabled"`
	TenantID       string `yaml:"tenant_id"`
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	SubscriptionID string `yaml:"subscription_id"`
}

// GCPCloudConfig for GCP Cloud Audit Log ingestion.
type GCPCloudConfig struct {
	Enabled         bool   `yaml:"enabled"`
	ProjectID       string `yaml:"project_id"`
	CredentialsFile string `yaml:"credentials_file"`
	PubSubTopic     string `yaml:"pubsub_topic"`
}

// SystemCollectorConfig for system metrics.
type SystemCollectorConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Interval string   `yaml:"interval"`
	Metrics  []string `yaml:"metrics"`
}

// FIMPathConfig is a single path to monitor.
type FIMPathConfig struct {
	Path           string   `yaml:"path"`
	Recursive      bool     `yaml:"recursive"`
	IgnorePatterns []string `yaml:"ignore_patterns"`
}

// FileIntegrityCollectorConfig for FIM.
type FileIntegrityCollectorConfig struct {
	Enabled       bool           `yaml:"enabled"`
	Interval      string         `yaml:"interval"`
	Paths         []FIMPathConfig `yaml:"paths"`
	HashAlgorithms []string      `yaml:"hash_algorithms"`
	ScanOnStart   bool           `yaml:"scan_on_start"`
}

// LogSourceConfig is a single log source.
type LogSourceConfig struct {
	Type             string   `yaml:"type"`
	Path             string   `yaml:"path"`
	Tags             []string `yaml:"tags"`
	MultilinePattern string   `yaml:"multiline_pattern"`
	Units            []string `yaml:"units"`
	Channels         []string `yaml:"channels"`
}

// LogsCollectorConfig for log collection.
type LogsCollectorConfig struct {
	Enabled        bool             `yaml:"enabled"`
	Sources        []LogSourceConfig `yaml:"sources"`
	MaxLineLength  int              `yaml:"max_line_length"`
	MaxBufferSize  int              `yaml:"max_buffer_size"`
}

// ProcessCollectorConfig for process monitoring.
type ProcessCollectorConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

// NetworkCollectorConfig for network connections.
type NetworkCollectorConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

// VulnerabilityCollectorConfig for optional CVE scanning.
type VulnerabilityCollectorConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Interval     string `yaml:"interval"`
	DBPath       string `yaml:"db_path"`
	DBUpdateURL  string `yaml:"db_update_url"`
}

// SCACollectorConfig for Security Configuration Assessment.
type SCACollectorConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Interval   string   `yaml:"interval"`
	PolicyDirs []string `yaml:"policy_dirs"`
}

// SCACheck is a single check within a policy.
type SCACheck struct {
	ID          int    `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Rationale   string `yaml:"rationale"`
	Remediation string `yaml:"remediation"`
	Compliance  string `yaml:"compliance"`
	Type        string `yaml:"type"` // file, process, command, registry
	Condition   string `yaml:"condition"` // all, any, none
	Rules       []string `yaml:"rules"`
}

// SCAPolicy is a full SCA policy definition.
type SCAPolicy struct {
	ID          string     `yaml:"id"`
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Refs        []string   `yaml:"references"`
	Checks      []SCACheck `yaml:"checks"`
}

// RootcheckCollectorConfig for rootkit detection.
type RootcheckCollectorConfig struct {
	Enabled           bool     `yaml:"enabled"`
	Interval          string   `yaml:"interval"`
	CheckHiddenProcs  bool     `yaml:"check_hidden_processes"`
	CheckHiddenPorts  bool     `yaml:"check_hidden_ports"`
	CheckRootkitFiles bool     `yaml:"check_rootkit_files"`
	CheckSUID         bool     `yaml:"check_suid"`
	ScanDirs          []string `yaml:"scan_dirs"`
}

// DockerCollectorConfig for container security monitoring.
type DockerCollectorConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Interval   string `yaml:"interval"`
	SocketPath string `yaml:"socket_path"`
}

// SyscollectorConfig for advanced asset inventory.
type SyscollectorConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interval  string `yaml:"interval"`
	Hardware  bool   `yaml:"hardware"`
	OS        bool   `yaml:"os"`
	Packages  bool   `yaml:"packages"`
	Ports     bool   `yaml:"ports"`
	NetIfaces bool   `yaml:"network_interfaces"`
	Users     bool   `yaml:"users"`
	Services  bool   `yaml:"services"`
	Hotfixes  bool   `yaml:"hotfixes"`
}

// RegistryCollectorConfig for Windows Registry monitoring.
type RegistryCollectorConfig struct {
	Enabled  bool               `yaml:"enabled"`
	Interval string             `yaml:"interval"`
	Keys     []RegistryKeyConfig `yaml:"keys"`
}

// RegistryKeyConfig is a single registry key to monitor.
type RegistryKeyConfig struct {
	Path      string `yaml:"path"`
	Recursive bool   `yaml:"recursive"`
}

// OsqueryCollectorConfig for Osquery integration.
type OsqueryCollectorConfig struct {
	Enabled    bool           `yaml:"enabled"`
	SocketPath string         `yaml:"socket_path"`
	BinaryPath string         `yaml:"binary_path"`
	Queries    []OsqueryQuery `yaml:"queries"`
}

// OsqueryQuery is a scheduled osquery query.
type OsqueryQuery struct {
	Name     string `yaml:"name"`
	Query    string `yaml:"query"`
	Interval string `yaml:"interval"`
}

// PerformanceConfig for resource limits and batching.
type PerformanceConfig struct {
	MaxCPUPercent  float64        `yaml:"max_cpu_percent"`
	MaxMemoryBytes uint64         `yaml:"max_memory_bytes"`
	MaxDiskBytes   uint64         `yaml:"max_disk_bytes"`
	BatchSize      int            `yaml:"batch_size"`
	FlushInterval  string         `yaml:"flush_interval"`
	QueueSize      int            `yaml:"queue_size"`
	DiskQueue      DiskQueueConfig `yaml:"disk_queue"`
}

// DiskQueueConfig controls the persistent WAL-backed queue.
type DiskQueueConfig struct {
	// Enabled turns on disk-backed persistence; RAM-only when false.
	Enabled bool `yaml:"enabled"`
	// Dir is the directory for WAL and checkpoint files.
	// Defaults to OS data dir when empty.
	Dir string `yaml:"dir"`
	// MaxBytes is the maximum WAL file size before writes are dropped (default 500 MB).
	MaxBytes int64 `yaml:"max_bytes"`
}

// LoadConfig reads YAML from path and overlays with environment variables.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func applyEnvOverrides(c *Config) {
	if v := os.Getenv("WATCHNODE_AGENT_ID"); v != "" {
		c.Agent.ID = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_URL"); v != "" {
		c.Manager.URL = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_CA"); v != "" {
		c.Manager.TLS.CA = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_CERT"); v != "" {
		c.Manager.TLS.Cert = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_KEY"); v != "" {
		c.Manager.TLS.Key = v
	}
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			Name:   "{{hostname}}",
			Labels: map[string]string{},
		},
		Manager: ManagerConfig{
			URL: "localhost:50051",
			Reconnect: ReconnectConfig{
				MaxAttempts:    0,
				InitialBackoff: "1s",
				MaxBackoff:     "5m",
			},
		},
		Collectors: CollectorsConfig{
			System: SystemCollectorConfig{
				Enabled:  true,
				Interval: "30s",
				Metrics:  []string{"cpu", "memory", "disk", "network", "processes"},
			},
			FileIntegrity: FileIntegrityCollectorConfig{
				Enabled:        true,
				Interval:       "5m",
				Paths:          []FIMPathConfig{},
				HashAlgorithms: []string{"sha256"},
				ScanOnStart:    true,
			},
			Logs: LogsCollectorConfig{
				Enabled:        true,
				Sources:        []LogSourceConfig{},
				MaxLineLength:  1048576,
				MaxBufferSize:  10485760,
			},
			Process: ProcessCollectorConfig{
				Enabled:  true,
				Interval: "30s",
			},
			Network: NetworkCollectorConfig{
				Enabled:  true,
				Interval: "30s",
			},
			Vulnerability: VulnerabilityCollectorConfig{
				Enabled:  false,
				Interval: "24h",
			},
			SCA: SCACollectorConfig{
				Enabled:    true,
				Interval:   "12h",
				PolicyDirs: []string{"/etc/watchnode/sca/policies"},
			},
			Rootcheck: RootcheckCollectorConfig{
				Enabled:           true,
				Interval:          "12h",
				CheckHiddenProcs:  true,
				CheckHiddenPorts:  true,
				CheckRootkitFiles: true,
				CheckSUID:         true,
				ScanDirs:          []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp"},
			},
			Docker: DockerCollectorConfig{
				Enabled:    false,
				Interval:   "60s",
				SocketPath: "/var/run/docker.sock",
			},
			Syscollector: SyscollectorConfig{
				Enabled:   true,
				Interval:  "1h",
				Hardware:  true,
				OS:        true,
				Packages:  true,
				Ports:     true,
				NetIfaces: true,
				Users:     true,
			},
			Registry: RegistryCollectorConfig{
				Enabled:  false,
				Interval: "5m",
				Keys:     nil,
			},
			Osquery: OsqueryCollectorConfig{
				Enabled:    false,
				SocketPath: "/var/osquery/osquery.em",
				BinaryPath: "/usr/bin/osqueryi",
				Queries:    nil,
			},
		},
		ActiveResponse: ActiveResponseConfig{
			Enabled: true,
			AllowedCommands: []string{
				"kill-process",
				"restart-service",
				"disable-account",
				"firewall-drop",
			},
			CommandTimeoutSecs: 15,
		},
		Performance: PerformanceConfig{
			MaxCPUPercent:  20,
			MaxMemoryBytes: 268435456,
			MaxDiskBytes:   1073741824,
			BatchSize:      1000,
			FlushInterval:  "30s",
			QueueSize:      10000,
			DiskQueue: DiskQueueConfig{
				Enabled:  true,
				Dir:      "",
				MaxBytes: 500 * 1024 * 1024,
			},
		},
	}
}

// ConfigPaths returns default config search paths for the platform.
func ConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/etc/watchnode/agent/config.yaml",
		filepath.Join(home, ".watchnode", "config.yaml"),
		"config.yaml",
	}
}

// ParseDuration parses a duration string with defaults.
func ParseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}
