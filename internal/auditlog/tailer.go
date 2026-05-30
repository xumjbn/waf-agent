// Package auditlog 周期性 tail 引擎的攻击/审计日志，把每条事件解析成攻击日志
// 上报给 waf-control，并累计拦截计数（供 agent 心跳算真实拦截率）。
//
// 解析格式由引擎决定（engine.ParseAuditLine）—— modsec JSON / 雷池日志 / ...，
// tailer 本身与具体引擎无关：只负责增量读文件 + 把解析结果交给 reporter。
package auditlog

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/waf-agent/internal/engine"
	"github.com/waf-agent/internal/reporter"
)

type Tailer struct {
	engine engine.Engine
	path   string
	rep    *reporter.Reporter
	offset int64
}

// New 用引擎的审计日志路径 + 解析器构造 tailer。path 空时（引擎不走文件日志）
// 调用方应跳过启动。
func New(eng engine.Engine, rep *reporter.Reporter) *Tailer {
	return &Tailer{engine: eng, path: eng.AuditLogPath(), rep: rep}
}

// Run 每 intervalSec 秒轮询一次审计日志，直到 ctx 取消。
func (t *Tailer) Run(ctx context.Context, intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	slog.Info("audit log tailer started", "engine", t.engine.Name(), "path", t.path, "interval_sec", intervalSec)
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
	rec, ok := t.engine.ParseAuditLine(line)
	if !ok {
		return
	}
	if rec.Blocked {
		t.rep.IncBlocked()
	}
	t.rep.PushAttackLog(reporter.AttackLogPayload{
		NodeID:     0, // control 端按 hostname 解析 node_id
		SrcIP:      rec.SrcIP,
		AttackType: rec.AttackType,
		RuleID:     rec.RuleID,
		Action:     rec.Action,
		Payload:    rec.Payload,
		Method:     rec.Method,
		URI:        rec.URI,
		UserAgent:  rec.UserAgent,
		OccurredAt: time.Now(),
	})
}
