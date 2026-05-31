package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/waf-agent/internal/config"
)

// CaddyEngine 是 Caddy + OWASP Coraza 引擎 —— OpenWAF 里唯一「开源 + 语义(词法级)
// + Go 原生 + CRS v4 兼容」且完全可控的检测引擎。
//
// 形态：Caddy 当宿主（反代 / 自动 HTTPS / HTTP3 / 证书续期），coraza-caddy 模块当
// WAF 中间件，跑 OWASP Core Rule Set v4 + libinjection-go 词法语义检测。需用 xcaddy
// 把 coraza-caddy 编进 caddy 二进制（见 deploy/caddy）。
//
// 与 NginxEngine 形态一致（都是「写盘 + validate + reload」外部进程），因此干净套进
// Engine 抽象：
//   ApplySite      —— 写站点反代片段到 [caddy].config_dir/{domain}.caddy（import 进主 Caddyfile）
//   ApplyPolicy    —— 写每站点 Coraza/CRS 规则到 [caddy].coraza_dir/{domain}.conf
//   Reload         —— caddy reload --config <Caddyfile>（不停机）
//   Test           —— caddy validate --config <Caddyfile>
//   CollectRuntime —— 抓 Caddy admin Prometheus 指标（caddy_http_requests_total）
//   ParseAuditLine —— Coraza JSON 审计日志（字段与 modsec 不同，见 corazaAuditEntry）
type CaddyEngine struct {
	cfg *config.Config
}

func NewCaddyEngine(cfg *config.Config) *CaddyEngine {
	return &CaddyEngine{cfg: cfg}
}

func (e *CaddyEngine) Name() string { return "caddy-coraza" }

// ApplySite 写站点反代片段。payload 是 control 下发的 Caddy 站点配置（Caddyfile 片段）。
func (e *CaddyEngine) ApplySite(ctx context.Context, domain string, payload []byte) error {
	if domain == "" || domain == "default" {
		domain = caddyExtractDomain(payload)
	}
	if domain == "" || domain == "unknown" {
		return fmt.Errorf("无法从配置确定站点域名")
	}
	slog.Info("applying caddy site config", "domain", domain)

	dst := filepath.Join(e.cfg.Caddy.ConfigDir, domain+".caddy")
	if err := e.writeAtomic(dst, payload); err != nil {
		return err
	}
	if err := e.Test(ctx); err != nil {
		e.restoreBak(dst)
		_ = e.Reload(ctx) // 尽力回滚到上一份可用配置
		return fmt.Errorf("caddy validate 失败（站点）: %w", err)
	}
	return e.Reload(ctx)
}

// ApplyPolicy 写每站点 Coraza/CRS 规则（SecLang）。payload 是 control 下发的规则文本
// （SecRule / CRS 覆盖 / 规则排除）。站点片段通过 coraza 指令 include 引用本文件。
func (e *CaddyEngine) ApplyPolicy(ctx context.Context, domain string, payload []byte) error {
	if domain == "" {
		domain = "default"
	}
	slog.Info("applying coraza policy", "domain", domain)

	dst := filepath.Join(e.cfg.Caddy.CorazaDir, domain+".conf")
	if err := e.writeAtomic(dst, payload); err != nil {
		return err
	}
	if err := e.Test(ctx); err != nil {
		e.restoreBak(dst)
		_ = e.Reload(ctx)
		return fmt.Errorf("caddy validate 失败（规则）: %w", err)
	}
	return e.Reload(ctx)
}

func (e *CaddyEngine) Reload(ctx context.Context) error {
	cmd := e.cfg.Caddy.ReloadCmd
	if cmd == "" {
		cmd = "caddy reload --config " + e.caddyfile()
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *CaddyEngine) Test(ctx context.Context) error {
	cmd := e.cfg.Caddy.TestCmd
	if cmd == "" {
		cmd = "caddy validate --config " + e.caddyfile()
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *CaddyEngine) AuditLogPath() string { return e.cfg.Caddy.AuditLog }

func (e *CaddyEngine) caddyfile() string {
	if e.cfg.Caddy.Caddyfile != "" {
		return e.cfg.Caddy.Caddyfile
	}
	return "/etc/caddy/Caddyfile"
}

// --- 文件落盘（原子写 + 备份，镜像 applier.NginxApplier 的约定） ---

func (e *CaddyEngine) writeAtomic(dst string, payload []byte) error {
	if dir := filepath.Dir(dst); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("建目录 %s: %w", dir, err)
		}
	}
	if e.cfg.Caddy.BackupEnabled {
		if data, err := os.ReadFile(dst); err == nil {
			if err := os.WriteFile(dst+".bak", data, 0o644); err != nil {
				slog.Warn("备份 caddy 配置失败", "path", dst+".bak", "error", err)
			}
		}
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return fmt.Errorf("写 caddy 配置: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename caddy 配置: %w", err)
	}
	return nil
}

func (e *CaddyEngine) restoreBak(dst string) {
	if !e.cfg.Caddy.BackupEnabled {
		return
	}
	if data, err := os.ReadFile(dst + ".bak"); err == nil {
		_ = os.WriteFile(dst, data, 0o644)
	}
}

// caddyExtractDomain 从 Caddyfile 站点块首行抽站点地址：
//   `example.com {` 或 `example.com, www.example.com {` 或 `https://example.com {`
func caddyExtractDomain(payload []byte) string {
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(line, "{")), "{")
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if len(fields) == 0 {
			continue
		}
		d := strings.TrimPrefix(fields[0], "https://")
		d = strings.TrimPrefix(d, "http://")
		if d != "" && d != "{" {
			return d
		}
	}
	return "unknown"
}

// --- 运行时指标：Caddy admin Prometheus 端点(/metrics) ---

func (e *CaddyEngine) CollectRuntime(ctx context.Context) RuntimeStats {
	url := e.cfg.Caddy.MetricsURL
	if url == "" {
		return RuntimeStats{Available: false}
	}
	total, inflight, err := scrapeCaddyMetrics(ctx, url)
	if err != nil {
		return RuntimeStats{Available: false}
	}
	return RuntimeStats{
		TotalRequests:     total,
		ActiveConnections: inflight,
		Available:         true,
	}
}

// scrapeCaddyMetrics 抓 Caddy admin 的 Prometheus 文本指标，累加：
//   caddy_http_requests_total      —— 累计请求数（调用方两次采样差 / 时间差算 RPS）
//   caddy_http_requests_in_flight  —— 进行中请求数（近似活动连接）
func scrapeCaddyMetrics(ctx context.Context, url string) (total int64, inflight int64, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("caddy metrics %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, 0, err
	}
	text := string(body)
	return int64(sumPromMetric(text, "caddy_http_requests_total")),
		int64(sumPromMetric(text, "caddy_http_requests_in_flight")), nil
}

// sumPromMetric 把 Prometheus 文本里某指标名的所有 series 值求和（忽略 # 注释行）。
// 例如 caddy_http_requests_total{handler=...,server=...} 跨 label 累加成总请求数。
func sumPromMetric(text, name string) float64 {
	var sum float64
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' || !strings.HasPrefix(ln, name) {
			continue
		}
		// 名称后必须是 '{'（带 label）或空白（无 label），避免 _total 误匹配 _total_xxx
		rest := ln[len(name):]
		if rest != "" && rest[0] != '{' && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			sum += v
		}
	}
	return sum
}

// --- 攻击日志：Coraza JSON 审计（SecAuditLogFormat JSON） ---
//
// Coraza 的审计 JSON 与 ModSecurity v3 同形但字段名不同（核实自 corazawaf/coraza
// internal/auditlog/auditlog.go）：response 用 status（非 http_code），规则号在
// messages[].data.id（int，非 details.ruleId），且 transaction.is_interrupted 直接
// 标识是否被拦截 —— 比猜 HTTP 403 更可靠。request.headers 是 map[string][]string。

type corazaAuditEntry struct {
	Transaction struct {
		ClientIP      string `json:"client_ip"`
		IsInterrupted bool   `json:"is_interrupted"`
		Request       struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
		Response struct {
			Status int `json:"status"`
		} `json:"response"`
	} `json:"transaction"`
	Messages []struct {
		Message string `json:"message"`
		Data    struct {
			ID   int      `json:"id"`
			Msg  string   `json:"msg"`
			Data string   `json:"data"`
			Tags []string `json:"tags"`
		} `json:"data"`
	} `json:"messages"`
}

func (e *CaddyEngine) ParseAuditLine(line []byte) (AttackRecord, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || trimmed[0] != '{' {
		return AttackRecord{}, false
	}
	var a corazaAuditEntry
	if err := json.Unmarshal([]byte(trimmed), &a); err != nil {
		return AttackRecord{}, false
	}
	tx := a.Transaction
	// 只上报触发了规则的事务；纯访问审计（messages 空）跳过
	if tx.ClientIP == "" || len(a.Messages) == 0 {
		return AttackRecord{}, false
	}
	m0 := a.Messages[0]
	ruleID := ""
	if m0.Data.ID > 0 {
		ruleID = strconv.Itoa(m0.Data.ID)
	}
	attackType := classifyCorazaAttack(m0.Data.Tags, firstNonEmpty(m0.Message, m0.Data.Msg))
	blocked := tx.IsInterrupted || tx.Response.Status == 403 || tx.Response.Status == 406
	action := "log"
	if blocked {
		action = "block"
	}
	ua := ""
	if h := tx.Request.Headers["User-Agent"]; len(h) > 0 {
		ua = h[0]
	}
	return AttackRecord{
		SrcIP:      tx.ClientIP,
		AttackType: attackType,
		RuleID:     ruleID,
		Action:     action,
		Payload:    m0.Data.Data,
		Method:     tx.Request.Method,
		URI:        tx.Request.URI,
		UserAgent:  ua,
		Blocked:    blocked,
	}, true
}

// classifyCorazaAttack 优先用 CRS 规则 tag（attack-sqli / attack-xss / ...）分类——
// 这是 CRS 规则自带的结构化标签，比文本匹配可靠；tag 未命中再退回 message 文本分类
// （复用 nginx.go 的 classifyAttack）。
func classifyCorazaAttack(tags []string, msg string) string {
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "attack-sqli":
			return "SQLi"
		case "attack-xss":
			return "XSS"
		case "attack-rce", "attack-injection-generic":
			return "RCE"
		case "attack-lfi":
			return "LFI"
		case "attack-rfi":
			return "RFI"
		case "attack-protocol":
			return "Protocol"
		case "attack-reputation-scanner":
			return "BOT"
		}
	}
	return classifyAttack(msg)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
