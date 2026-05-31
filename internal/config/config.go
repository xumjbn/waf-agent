package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Agent     AgentConfig     `mapstructure:"agent"`
	Server    ServerConfig    `mapstructure:"server"`
	Engine    EngineConfig    `mapstructure:"engine"`
	Nginx     NginxConfig     `mapstructure:"nginx"`
	Caddy     CaddyConfig     `mapstructure:"caddy"`
	SafeLine  SafeLineConfig  `mapstructure:"safeline"`
	Collector CollectorConfig `mapstructure:"collector"`
	Reporter  ReporterConfig  `mapstructure:"reporter"`
}

// EngineConfig 选择后端代理/检测引擎。type 取 nginx / openresty / caddy-coraza /
// safeline。空默认 nginx。切换方式：改本配置后重启 agent（启动期装配）。
type EngineConfig struct {
	Type string `mapstructure:"type"`
}

// CaddyConfig 是 Caddy + OWASP Coraza 引擎参数（仅 [engine].type = "caddy-coraza"
// 时生效）。Caddy 当宿主（反代/自动 HTTPS），coraza-caddy 模块跑 CRS v4 检测。
type CaddyConfig struct {
	ConfigDir     string `mapstructure:"config_dir"` // 站点反代片段目录（{domain}.caddy，import 进主 Caddyfile）
	CorazaDir     string `mapstructure:"coraza_dir"` // 每站点 Coraza/CRS 规则目录（{domain}.conf）
	Caddyfile     string `mapstructure:"caddyfile"`  // 主 Caddyfile 路径（reload/validate 用）
	ReloadCmd     string `mapstructure:"reload_cmd"` // 留空默认 `caddy reload --config <caddyfile>`
	TestCmd       string `mapstructure:"test_cmd"`   // 留空默认 `caddy validate --config <caddyfile>`
	BackupEnabled bool   `mapstructure:"backup_enabled"`
	// MetricsURL 指向 Caddy admin 的 Prometheus 端点（默认 http://127.0.0.1:2019/metrics）。
	// 配了才采集真实 RPS / 进行中请求；留空则 RPS=0。
	MetricsURL string `mapstructure:"metrics_url"`
	// AuditLog 指向 Coraza JSON 审计日志（SecAuditLogFormat JSON）。配了才启用 tailer
	// —— 真实采集攻击事件上报 + 算拦截率。留空则不采集。
	AuditLog string `mapstructure:"audit_log"`
}

// SafeLineConfig 雷池（长亭 SafeLine）引擎对接参数。当前为骨架，
// 实际对接雷池管理 API 时填充。
type SafeLineConfig struct {
	APIBaseURL string `mapstructure:"api_base_url"` // 雷池管理 API，如 https://safeline-mgt:9443
	APIToken   string `mapstructure:"api_token"`
	AuditLog   string `mapstructure:"audit_log"` // 雷池攻击日志路径（若走文件）
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
	// AuditLog 指向 modsec JSON 审计日志（SecAuditLogFormat JSON）。配了才启用
	// 审计日志 tailer —— 真实采集攻击事件上报 + 计算拦截率。留空则不采集。
	AuditLog string `mapstructure:"audit_log"`
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
