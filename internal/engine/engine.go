// Package engine 把「后端代理/检测引擎」抽象成可插拔接口，支持 NGINX(+ModSec)、
// OpenResty、雷池（SafeLine）等多种引擎，通过 agent.toml 的 [engine].type 选择。
//
// 之前 agent 把 NGINX + ModSecurity 写死在 applier / metrics / auditlog 三处。
// 这里统一到 Engine 接口，每种引擎封装各自的：配置下发、reload、运行时指标源、
// 攻击日志路径 + 解析格式。切换方式：改配置重启 agent（启动期按 type 装配）。
package engine

import (
	"context"

	"github.com/waf-agent/internal/config"
)

// RuntimeStats 是引擎运行时指标快照。TotalRequests 是累计请求数（调用方两次
// 采样差 / 时间差算 RPS 速率）。Available=false 表示该引擎没有可用指标源。
type RuntimeStats struct {
	TotalRequests     int64
	ActiveConnections int64
	Available         bool
}

// AttackRecord 是从引擎攻击/审计日志解析出的一条事件（引擎无关结构）。
type AttackRecord struct {
	SrcIP      string
	AttackType string
	RuleID     string
	Action     string // block / log
	Payload    string
	Method     string
	URI        string
	UserAgent  string
	Blocked    bool
}

// Engine 是可插拔后端引擎的统一接口。
type Engine interface {
	// Name 返回引擎标识（nginx / openresty / safeline），用于注册上报 + 日志。
	Name() string

	// ApplySite 下发站点（反代/虚拟主机）配置。
	ApplySite(ctx context.Context, domain string, payload []byte) error
	// ApplyPolicy 下发检测策略（规则）配置。
	ApplyPolicy(ctx context.Context, domain string, payload []byte) error
	// Reload 让引擎重载配置（不重启进程）。
	Reload(ctx context.Context) error
	// Test 校验当前配置是否合法。
	Test(ctx context.Context) error

	// CollectRuntime 返回运行时指标（rps 源 / 活动连接）。不支持时 Available=false。
	CollectRuntime(ctx context.Context) RuntimeStats

	// AuditLogPath 返回攻击/审计日志文件路径（空=不走文件 tailer）。
	AuditLogPath() string
	// ParseAuditLine 把一行审计日志解析成 AttackRecord。ok=false 表示跳过此行。
	ParseAuditLine(line []byte) (AttackRecord, bool)
}

// New 按 cfg.Engine.Type 装配引擎。空 / 未知类型回退到 nginx。
func New(cfg *config.Config) Engine {
	switch normalizeType(cfg.Engine.Type) {
	case "openresty":
		return NewOpenRestyEngine(cfg)
	case "safeline":
		return NewSafeLineEngine(cfg)
	default:
		return NewNginxEngine(cfg)
	}
}

func normalizeType(t string) string {
	switch t {
	case "openresty", "open-resty", "openrestry": // 容忍常见拼写
		return "openresty"
	case "safeline", "safe-line", "雷池", "leichi":
		return "safeline"
	default:
		return "nginx"
	}
}
