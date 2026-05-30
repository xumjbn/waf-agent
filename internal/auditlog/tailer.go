// Package auditlog 周期性 tail modsec 的 JSON 审计日志（SecAuditLogFormat JSON），
// 把每条被检测/拦截的事务解析成攻击日志上报给 waf-control，并累计拦截计数
// （供 agent 心跳算真实拦截率）。
//
// 之前 agent 根本没有日志 tailer —— reporter.PushAttackLog 从未被调用，
// 整个『从防护节点采集真实攻击』链路是断的。这里补上。
//
// 设计：增量轮询文件（记录 offset），按行解析 JSON；文件被轮转（size < offset）
// 时重置 offset。解析尽量宽容，单行坏了跳过不影响整体。
package auditlog

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/waf-agent/internal/reporter"
)

// auditEntry 是 modsec JSON 审计格式中我们关心的子集。
type auditEntry struct {
	Transaction struct {
		ClientIP string `json:"client_ip"`
		Host     string `json:"host_ip"`
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
				RuleID   string `json:"ruleId"`
				Data     string `json:"data"`
				Severity string `json:"severity"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

type Tailer struct {
	path   string
	nodeID string
	rep    *reporter.Reporter
	offset int64
}

func New(path, nodeID string, rep *reporter.Reporter) *Tailer {
	return &Tailer{path: path, nodeID: nodeID, rep: rep}
}

// Run 每 intervalSec 秒轮询一次审计日志，直到 ctx 取消。
func (t *Tailer) Run(ctx context.Context, intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	slog.Info("audit log tailer started", "path", t.path, "interval_sec", intervalSec)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.poll()
		}
	}
}

func (t *Tailer) poll() {
	f, err := os.Open(t.path)
	if err != nil {
		slog.Debug("audit log not readable", "path", t.path, "error", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}
	// 文件被轮转（变小）→ 从头读。
	if info.Size() < t.offset {
		t.offset = 0
	}
	if _, err := f.Seek(t.offset, 0); err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 容纳长行
	var consumed int64
	for scanner.Scan() {
		line := scanner.Bytes()
		consumed += int64(len(line)) + 1 // +1 换行符
		t.handleLine(line)
	}
	t.offset += consumed
}

func (t *Tailer) handleLine(line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || trimmed[0] != '{' {
		return
	}
	var e auditEntry
	if err := json.Unmarshal([]byte(trimmed), &e); err != nil {
		return
	}
	tx := e.Transaction
	if tx.ClientIP == "" {
		return
	}

	ruleID, attackType, data := "", "", ""
	if len(tx.Messages) > 0 {
		ruleID = tx.Messages[0].Details.RuleID
		data = tx.Messages[0].Details.Data
		attackType = classifyAttack(tx.Messages[0].Message)
	}

	// http_code 403/406 视为被拦截。
	blocked := tx.Response.HTTPCode == 403 || tx.Response.HTTPCode == 406
	action := "log"
	if blocked {
		action = "block"
		t.rep.IncBlocked()
	}

	t.rep.PushAttackLog(reporter.AttackLogPayload{
		NodeID:     0, // control 端按 hostname 解析 node_id
		SrcIP:      tx.ClientIP,
		AttackType: attackType,
		RuleID:     ruleID,
		Action:     action,
		Payload:    data,
		Method:     tx.Request.Method,
		URI:        tx.Request.URI,
		UserAgent:  tx.Request.Headers["User-Agent"],
		OccurredAt: time.Now(),
	})
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
