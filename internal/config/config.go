package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Agent     AgentConfig     `mapstructure:"agent"`
	Server    ServerConfig    `mapstructure:"server"`
	Nginx     NginxConfig     `mapstructure:"nginx"`
	Collector CollectorConfig `mapstructure:"collector"`
}

type AgentConfig struct {
	NodeID   string `mapstructure:"node_id"`
	Hostname string `mapstructure:"hostname"`
	DataDir  string `mapstructure:"data_dir"`
}

type ServerConfig struct {
	Address             string `mapstructure:"address"`
	TLSEnabled          bool   `mapstructure:"tls_enabled"`
	TLSCACert           string `mapstructure:"tls_ca_cert"`
	ReconnectBackoffSec int    `mapstructure:"reconnect_backoff_sec"`
}

type NginxConfig struct {
	ConfigDir      string `mapstructure:"config_dir"`
	ModsecDir      string `mapstructure:"modsec_dir"`
	SSLDir         string `mapstructure:"ssl_dir"`
	ReloadCmd      string `mapstructure:"reload_cmd"`
	TestCmd        string `mapstructure:"test_cmd"`
	BackupEnabled  bool   `mapstructure:"backup_enabled"`
}

type CollectorConfig struct {
	IntervalSec int `mapstructure:"interval_sec"`
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("toml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if cfg.Agent.Hostname == "" {
		hn, _ := os.Hostname()
		cfg.Agent.Hostname = hn
	}
	if cfg.Agent.NodeID == "" {
		cfg.Agent.NodeID = cfg.Agent.Hostname
	}
	if cfg.Server.ReconnectBackoffSec <= 0 {
		cfg.Server.ReconnectBackoffSec = 5
	}
	if cfg.Collector.IntervalSec <= 0 {
		cfg.Collector.IntervalSec = 10
	}

	return &cfg, nil
}
