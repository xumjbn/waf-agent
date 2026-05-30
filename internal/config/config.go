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
	Reporter  ReporterConfig  `mapstructure:"reporter"`
}

// ReporterConfig 控制 internal/reporter（REST 上报器）。
// BaseURL = waf-control HTTP 入口，例如 http://control.local:9200
// AuthToken = 静态 token（管理员账号 issue），用于 Bearer 鉴权
type ReporterConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	BaseURL   string `mapstructure:"base_url"`
	AuthToken string `mapstructure:"auth_token"`
}

type AgentConfig struct {
	NodeID   string  `mapstructure:"node_id"`
	Hostname string  `mapstructure:"hostname"`
	DataDir  string  `mapstructure:"data_dir"`
	SiteIDs  []int64 `mapstructure:"site_ids"` // 该节点接管的站点 ID 列表，用于 PUT /sites/{id}/metrics
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
	// StatusURL 指向 nginx stub_status 端点（如 http://127.0.0.1/nginx_status）。
	// 配了才采集真实 RPS / 活动连接；留空则 RPS=0（保持旧行为）。
	StatusURL string `mapstructure:"status_url"`
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
