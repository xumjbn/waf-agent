package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/waf-agent/internal/config"
)

// SafeLineEngine 是雷池（长亭 SafeLine）引擎的接口骨架。
//
// 雷池架构与 NGINX/OpenResty 不同：它是独立产品（mgt 管理面 + detector 检测引擎
// + tengine 反代 + 数据库），站点配置通过雷池管理 API 下发，攻击日志走雷池自己的
// 存储 / API。因此本引擎的配置下发 / reload 需对接雷池管理 API（api_base_url +
// api_token，见 [safeline] 配置块）。
//
// 当前为骨架：实现 Engine 接口使「可编译可切换」，但实际动作返回明确的未对接错误，
// 不假装成功。落地时填充各方法（对接雷池 OpenAPI）。
type SafeLineEngine struct {
	cfg *config.Config
}

func NewSafeLineEngine(cfg *config.Config) *SafeLineEngine {
	return &SafeLineEngine{cfg: cfg}
}

func (e *SafeLineEngine) Name() string { return "safeline" }

func (e *SafeLineEngine) ApplySite(ctx context.Context, domain string, payload []byte) error {
	// TODO(safeline): 调用雷池管理 API POST /api/open/site 下发站点。
	return e.notImplemented("ApplySite")
}

func (e *SafeLineEngine) ApplyPolicy(ctx context.Context, domain string, payload []byte) error {
	// TODO(safeline): 雷池检测策略通过其策略 API 配置，非文件下发。
	return e.notImplemented("ApplyPolicy")
}

func (e *SafeLineEngine) Reload(ctx context.Context) error {
	// 雷池配置经 API 即时生效，通常无需显式 reload。
	return e.notImplemented("Reload")
}

func (e *SafeLineEngine) Test(ctx context.Context) error {
	// 雷池配置校验由其管理面负责。
	return nil
}

// CollectRuntime —— 雷池指标走其 API（QPS / 拦截数等）。骨架暂不可用。
func (e *SafeLineEngine) CollectRuntime(ctx context.Context) RuntimeStats {
	// TODO(safeline): GET 雷池统计 API 取 QPS / 活动连接。
	return RuntimeStats{Available: false}
}

// AuditLogPath —— 雷池攻击日志若导出为文件（[safeline].audit_log）则 tail，
// 否则应走雷池日志 API（骨架暂用文件路径）。
func (e *SafeLineEngine) AuditLogPath() string { return e.cfg.SafeLine.AuditLog }

// safeLineLogEntry 是雷池攻击日志的假定 JSON 结构（占位，落地时按雷池实际格式调整）。
type safeLineLogEntry struct {
	SrcIP      string `json:"src_ip"`
	Method     string `json:"method"`
	URLPath    string `json:"url_path"`
	Action     string `json:"action"` // deny / log
	Module     string `json:"attack_type"`
	RuleID     string `json:"rule_id"`
	UserAgent  string `json:"user_agent"`
	Payload    string `json:"payload"`
}

func (e *SafeLineEngine) ParseAuditLine(line []byte) (AttackRecord, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || trimmed[0] != '{' {
		return AttackRecord{}, false
	}
	var s safeLineLogEntry
	if err := json.Unmarshal([]byte(trimmed), &s); err != nil {
		return AttackRecord{}, false
	}
	if s.SrcIP == "" {
		return AttackRecord{}, false
	}
	blocked := s.Action == "deny" || s.Action == "block"
	action := "log"
	if blocked {
		action = "block"
	}
	return AttackRecord{
		SrcIP:      s.SrcIP,
		AttackType: s.Module,
		RuleID:     s.RuleID,
		Action:     action,
		Payload:    s.Payload,
		Method:     s.Method,
		URI:        s.URLPath,
		UserAgent:  s.UserAgent,
		Blocked:    blocked,
	}, true
}

func (e *SafeLineEngine) notImplemented(op string) error {
	return fmt.Errorf("safeline 引擎 %s 待对接雷池管理 API（[safeline].api_base_url=%q）",
		op, e.cfg.SafeLine.APIBaseURL)
}
