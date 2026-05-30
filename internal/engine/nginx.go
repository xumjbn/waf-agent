package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/waf-agent/internal/applier"
	"github.com/waf-agent/internal/config"
)

// NginxEngine 是 NGINX + ModSecurity 引擎：
//   配置下发走 applier（写 conf + nginx -t + reload）；
//   运行时指标抓 stub_status；攻击日志解析 modsec JSON 审计格式。
type NginxEngine struct {
	cfg     *config.Config
	applier *applier.Applier
	name    string
}

func NewNginxEngine(cfg *config.Config) *NginxEngine {
	return &NginxEngine{cfg: cfg, applier: applier.New(cfg), name: "nginx"}
}

func (e *NginxEngine) Name() string { return e.name }

func (e *NginxEngine) ApplySite(ctx context.Context, domain string, payload []byte) error {
	return e.applier.ApplyNginx(ctx, domain, payload)
}

func (e *NginxEngine) ApplyPolicy(ctx context.Context, domain string, payload []byte) error {
	return e.applier.ApplyModsec(ctx, domain, payload)
}

func (e *NginxEngine) Reload(ctx context.Context) error {
	return e.applier.Reload(ctx)
}

func (e *NginxEngine) Test(ctx context.Context) error {
	if e.cfg.Nginx.TestCmd == "" {
		return nil
	}
	out, err := exec.CommandContext(ctx, "sh", "-c", e.cfg.Nginx.TestCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), string(out))
	}
	return nil
}

func (e *NginxEngine) AuditLogPath() string { return e.cfg.Nginx.AuditLog }

// --- 运行时指标：nginx stub_status ---

func (e *NginxEngine) CollectRuntime(ctx context.Context) RuntimeStats {
	url := e.cfg.Nginx.StatusURL
	if url == "" {
		return RuntimeStats{Available: false}
	}
	st, err := scrapeStubStatus(ctx, url)
	if err != nil {
		return RuntimeStats{Available: false}
	}
	return RuntimeStats{
		TotalRequests:     st.totalRequests,
		ActiveConnections: st.activeConnections,
		Available:         true,
	}
}

type stubStatus struct {
	activeConnections int64
	totalRequests     int64
}

func scrapeStubStatus(ctx context.Context, url string) (*stubStatus, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nginx status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	return parseStubStatus(string(body)), nil
}

func parseStubStatus(text string) *stubStatus {
	lines := strings.Split(text, "\n")
	var st stubStatus
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "Active connections:") {
			_, _ = fmt.Sscanf(trimmed, "Active connections: %d", &st.activeConnections)
		}
		if strings.Contains(trimmed, "accepts") && strings.Contains(trimmed, "handled") {
			if i+1 < len(lines) {
				fields := strings.Fields(lines[i+1])
				if len(fields) >= 3 {
					_, _ = fmt.Sscanf(fields[2], "%d", &st.totalRequests)
				}
			}
		}
	}
	return &st
}

// --- 攻击日志：modsec JSON 审计格式 ---

type modsecAuditEntry struct {
	Transaction struct {
		ClientIP string `json:"client_ip"`
		Request  struct {
			Method  string            `json:"method"`
			URI     string            `json:"uri"`
			Headers map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				RuleID string `json:"ruleId"`
				Data   string `json:"data"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

func (e *NginxEngine) ParseAuditLine(line []byte) (AttackRecord, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || trimmed[0] != '{' {
		return AttackRecord{}, false
	}
	var m modsecAuditEntry
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return AttackRecord{}, false
	}
	tx := m.Transaction
	if tx.ClientIP == "" {
		return AttackRecord{}, false
	}
	ruleID, attackType, data := "", "", ""
	if len(tx.Messages) > 0 {
		ruleID = tx.Messages[0].Details.RuleID
		data = tx.Messages[0].Details.Data
		attackType = classifyAttack(tx.Messages[0].Message)
	}
	blocked := tx.Response.HTTPCode == 403 || tx.Response.HTTPCode == 406
	action := "log"
	if blocked {
		action = "block"
	}
	return AttackRecord{
		SrcIP:      tx.ClientIP,
		AttackType: attackType,
		RuleID:     ruleID,
		Action:     action,
		Payload:    data,
		Method:     tx.Request.Method,
		URI:        tx.Request.URI,
		UserAgent:  tx.Request.Headers["User-Agent"],
		Blocked:    blocked,
	}, true
}

// classifyAttack 从 modsec message 文本粗分攻击类型（喂前端类型标签）。
func classifyAttack(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "sql"):
		return "SQLi"
	case strings.Contains(m, "xss") || strings.Contains(m, "cross-site script"):
		return "XSS"
	case strings.Contains(m, "rce") || strings.Contains(m, "remote command") || strings.Contains(m, "os command"):
		return "RCE"
	case strings.Contains(m, "lfi") || strings.Contains(m, "file inclusion") || strings.Contains(m, "path traversal"):
		return "LFI"
	case strings.Contains(m, "rfi"):
		return "RFI"
	case strings.Contains(m, "scanner") || strings.Contains(m, "bot"):
		return "BOT"
	default:
		return "Generic"
	}
}
