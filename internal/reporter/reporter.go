// Package reporter 周期性把 agent 采集到的数据通过 waf-control 的 REST API
// 上报。当前实现仅覆盖三类：
//
//   - 攻击日志       POST /api/v1/logs/attack
//   - 命中计数       POST /api/v1/policies/{id}/hit
//   - 节点指标       PUT  /api/v1/sites/{site_id}/metrics  （仅当 cfg 里配了 site_id 时）
//
// gRPC 通道（heartbeat / config push / metrics RPC）由 grpcclient 维护；
// 这里走 REST 是因为 waf-control feat/backend-* 系列的 UI 富字段全部走 REST
// 端点，proto regen 流程暂未拉齐。等 proto 升级后可以把 REST 调用切回 gRPC。
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waf-agent/internal/config"
)

// AttackLogPayload 与 waf-control internal/domain/logs.AttackLog 字段一一对齐
// （migration 000011 起的 UI 富字段全集）。
type AttackLogPayload struct {
	NodeID     int64     `json:"node_id"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    int       `json:"src_port"`
	DstPort    int       `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	AttackType string    `json:"attack_type"`
	RuleID     string    `json:"rule_id"`
	Action     string    `json:"action"`
	Payload    string    `json:"payload"`
	OccurredAt time.Time `json:"occurred_at"`

	Region    string  `json:"region"`
	Country   string  `json:"country"`
	Lat       float64 `json:"lat"`
	Lng       float64 `json:"lng"`
	Site      string  `json:"site"`
	Domain    string  `json:"domain"`
	TypeLabel string  `json:"type_label"`
	TypeColor string  `json:"type_color"`
	Risk      string  `json:"risk"`
	Method    string  `json:"method"`
	URI       string  `json:"uri"`
	UserAgent string  `json:"user_agent"`
}

// SiteMetricsPayload 对齐 waf-control internal/domain/site.UpdateMetricsRequest。
type SiteMetricsPayload struct {
	RPS              float64   `json:"rps"`
	BlockedRate      float64   `json:"blocked_rate"`
	InstanceLabel    string    `json:"instance_label"`
	MetricsUpdatedAt time.Time `json:"metrics_updated_at"`
}

// Reporter 是周期性上报器；通过 PushAttackLog / RecordPolicyHit /
// PushSiteMetrics 把待发样本压入内部 buffer，定时 flush 给 waf-control。
type Reporter struct {
	cfg      *config.Config
	baseURL  string // 形如 http://control:9200
	authToken string
	httpCli  *http.Client

	mu          sync.Mutex
	attackQueue []AttackLogPayload
	hitQueue    map[int64]int64 // policyID -> delta
	siteQueue   map[int64]SiteMetricsPayload

	// blockedTotal 是审计日志 tailer 累计观察到的「被拦截」事件数（单调递增）。
	// conn.go 心跳读它的增量 / 请求增量算拦截率。用 atomic 避免锁竞争。
	blockedTotal atomic.Int64
}

// IncBlocked 由审计日志 tailer 在发现一条被拦截事件时调用。
func (r *Reporter) IncBlocked() { r.blockedTotal.Add(1) }

// BlockedTotal 返回累计被拦截事件数。
func (r *Reporter) BlockedTotal() int64 { return r.blockedTotal.Load() }

func New(cfg *config.Config, baseURL, token string) *Reporter {
	return &Reporter{
		cfg:       cfg,
		baseURL:   baseURL,
		authToken: token,
		httpCli:   &http.Client{Timeout: 10 * time.Second},
		hitQueue:  make(map[int64]int64),
		siteQueue: make(map[int64]SiteMetricsPayload),
	}
}

// PushAttackLog 缓冲一条富攻击日志。线程安全。
func (r *Reporter) PushAttackLog(p AttackLogPayload) {
	if p.OccurredAt.IsZero() {
		p.OccurredAt = time.Now()
	}
	r.mu.Lock()
	r.attackQueue = append(r.attackQueue, p)
	r.mu.Unlock()
}

// RecordPolicyHit 累加某条策略的命中次数。
func (r *Reporter) RecordPolicyHit(policyID int64, delta int64) {
	if delta <= 0 {
		delta = 1
	}
	r.mu.Lock()
	r.hitQueue[policyID] += delta
	r.mu.Unlock()
}

// PushSiteMetrics 替换某个 site 最新的 metrics 样本（同 ID 后写覆盖前写）。
func (r *Reporter) PushSiteMetrics(siteID int64, m SiteMetricsPayload) {
	if m.MetricsUpdatedAt.IsZero() {
		m.MetricsUpdatedAt = time.Now()
	}
	r.mu.Lock()
	r.siteQueue[siteID] = m
	r.mu.Unlock()
}

// Run 以 cfg.Collector.IntervalSec 间隔反复 flush，直到 ctx 取消。
func (r *Reporter) Run(ctx context.Context) {
	interval := time.Duration(r.cfg.Collector.IntervalSec) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.flush(ctx)
		}
	}
}

func (r *Reporter) flush(ctx context.Context) {
	r.mu.Lock()
	attacks := r.attackQueue
	hits := r.hitQueue
	sites := r.siteQueue
	r.attackQueue = nil
	r.hitQueue = make(map[int64]int64)
	r.siteQueue = make(map[int64]SiteMetricsPayload)
	r.mu.Unlock()

	for _, a := range attacks {
		if err := r.post(ctx, "/api/v1/logs/attack", a, nil); err != nil {
			slog.Warn("attack log upload failed", "error", err)
		}
	}
	for pid, delta := range hits {
		if err := r.post(ctx, fmt.Sprintf("/api/v1/policies/%d/hit", pid), map[string]int64{"delta": delta}, nil); err != nil {
			slog.Warn("policy hit upload failed", "policy_id", pid, "error", err)
		}
	}
	for sid, m := range sites {
		if err := r.put(ctx, fmt.Sprintf("/api/v1/sites/%d/metrics", sid), m); err != nil {
			slog.Warn("site metrics upload failed", "site_id", sid, "error", err)
		}
	}
	if len(attacks)+len(hits)+len(sites) > 0 {
		slog.Info("reporter flush", "attacks", len(attacks), "hits", len(hits), "sites", len(sites))
	}
}

func (r *Reporter) post(ctx context.Context, path string, body any, out any) error {
	return r.do(ctx, http.MethodPost, path, body, out)
}

func (r *Reporter) put(ctx context.Context, path string, body any) error {
	return r.do(ctx, http.MethodPut, path, body, nil)
}

func (r *Reporter) do(ctx context.Context, method, path string, body any, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, &buf)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.authToken)
	}
	res, err := r.httpCli.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s %s -> %d: %s", method, path, res.StatusCode, string(b))
	}
	if out != nil {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
