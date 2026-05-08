package manager

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
}

type ServerConfig struct {
	ListenAddress string    `yaml:"listen_address"`
	TLS           TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if v := os.Getenv("WATCHNODE_MANAGER_LISTEN"); v != "" {
		c.Server.ListenAddress = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_TLS_CERT"); v != "" {
		c.Server.TLS.Cert = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_TLS_KEY"); v != "" {
		c.Server.TLS.Key = v
	}
	if v := os.Getenv("WATCHNODE_MANAGER_TLS_CA"); v != "" {
		c.Server.TLS.CA = v
	}
	return &c, nil
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddress: "0.0.0.0:50051",
			TLS: TLSConfig{
				Cert: "scripts/certs/server.crt",
				Key:  "scripts/certs/server.key",
				CA:   "scripts/certs/ca.crt",
			},
		},
	}
}

