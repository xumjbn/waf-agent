package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/waf-agent/internal/config"
	"github.com/waf-agent/internal/reporter"
	pb "github.com/waf-control/proto/agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Client struct {
	cfg    *config.Config
	conn   *grpc.ClientConn
	agent  pb.AgentServiceClient
	apply  ConfigApplier
	report *reporter.Reporter // 可空：REST 上报器

	// nginx stub_status 采样上一次的累计请求数 + 时间，用于算 RPS 速率。
	prevRequests int64
	prevSampleAt time.Time
}

// AttachReporter 让 grpcclient 把心跳采集到的 ResourceUsage 同步推给 REST reporter。
func (c *Client) AttachReporter(r *reporter.Reporter) {
	c.report = r
}

type ConfigApplier interface {
	ApplyNginx(ctx context.Context, domain string, payload []byte) error
	ApplyModsec(ctx context.Context, domain string, payload []byte) error
	Reload(ctx context.Context) error
}

// configTypeCommand 与 control 端 agent.configTypeCommand 对齐（proto COMMAND=6）。
// proto3 枚举开放，regen 后可换成具名 pb.ConfigUpdate_COMMAND。
const configTypeCommand = pb.ConfigUpdate_ConfigType(6)

// agentCommand 对齐 control 端 agent.AgentCommand。
type agentCommand struct {
	CommandID string `json:"command_id"`
	Command   string `json:"command"`
	Reason    string `json:"reason,omitempty"`
}

func New(cfg *config.Config, apply ConfigApplier) *Client {
	return &Client{cfg: cfg, apply: apply}
}

func (c *Client) Connect(ctx context.Context) error {
	opts := []grpc.DialOption{}

	if c.cfg.Server.TLSEnabled {
		cred, err := loadTLS(c.cfg.Server.TLSCACert)
		if err != nil {
			return fmt.Errorf("load TLS: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(cred))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(ctx, c.cfg.Server.Address, opts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	c.conn = conn
	c.agent = pb.NewAgentServiceClient(conn)
	slog.Info("connected to control server", "addr", c.cfg.Server.Address)
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := c.runSession(ctx); err != nil {
			slog.Error("session ended", "error", err)
		}

		backoff := time.Duration(c.cfg.Server.ReconnectBackoffSec) * time.Second
		slog.Info("reconnecting", "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if err := c.Connect(ctx); err != nil {
			slog.Error("reconnect failed", "error", err)
			continue
		}
	}
}

func (c *Client) runSession(ctx context.Context) error {
	if c.conn == nil {
		if err := c.Connect(ctx); err != nil {
			return err
		}
	}
	defer c.conn.Close()

	// 1. Register
	regResp, err := c.agent.Register(ctx, &pb.RegisterRequest{
		NodeId:    c.cfg.Agent.NodeID,
		Hostname:  c.cfg.Agent.Hostname,
		IpAddress: getLocalIP(),
		Version:   "1.0.0",
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	slog.Info("registered", "assigned_id", regResp.AssignedId, "heartbeat_interval", regResp.HeartbeatIntervalSec)

	// 2. Start heartbeat + metrics goroutine
	hbInterval := time.Duration(regResp.HeartbeatIntervalSec) * time.Second
	if hbInterval < time.Second {
		hbInterval = 10 * time.Second
	}
	go c.heartbeatLoop(ctx, hbInterval)

	// 3. Start config push stream
	slog.Info("starting config stream")
	stream, err := c.agent.PushConfig(ctx, &pb.ConfigRequest{
		NodeId:         c.cfg.Agent.NodeID,
		CurrentVersion: "0",
	})
	if err != nil {
		return fmt.Errorf("start push config: %w", err)
	}

	for {
		update, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv config update: %w", err)
		}
		c.handleConfigUpdate(ctx, update)
	}
}

func (c *Client) handleConfigUpdate(ctx context.Context, update *pb.ConfigUpdate) {
	slog.Info("received config update", "version", update.Version, "type", update.Type.String())

	// COMMAND（值 6）：一次性命令，走独立分支。
	if update.Type == configTypeCommand {
		c.handleCommand(ctx, update.Payload)
		return
	}

	var applyErr error
	domain := "default"

	switch update.Type {
	case pb.ConfigUpdate_SITE, pb.ConfigUpdate_FULL:
		applyErr = c.apply.ApplyNginx(ctx, domain, update.Payload)
	case pb.ConfigUpdate_POLICY:
		applyErr = c.apply.ApplyModsec(ctx, domain, update.Payload)
	default:
		slog.Debug("ignoring config type", "type", update.Type.String())
		return
	}

	result := &pb.DeployResult{
		NodeId:    c.cfg.Agent.NodeID,
		Version:   update.Version,
		Type:      update.Type.String(),
		Success:   applyErr == nil,
		AppliedAt: update.Timestamp,
	}
	if applyErr != nil {
		result.Message = applyErr.Error()
		slog.Error("config apply failed", "version", update.Version, "error", applyErr)
	} else {
		result.Message = "applied"
		slog.Info("config applied", "version", update.Version)
	}

	// Report deploy result back to control plane
	rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.agent.ReportDeployResult(rctx, result); err != nil {
		slog.Warn("report deploy result failed", "error", err)
	}
}

// handleCommand 执行 control 下发的一次性命令（payload 为 JSON agentCommand）。
//   restart_service          优雅退出 → 容器/systemd 重启（PID1 退出即重启）
//   reload_config/sync_rules nginx -s reload，进程不退
func (c *Client) handleCommand(ctx context.Context, payload []byte) {
	var cmd agentCommand
	if err := json.Unmarshal(payload, &cmd); err != nil {
		slog.Warn("invalid command payload", "error", err)
		return
	}
	slog.Info("received command", "command", cmd.Command, "command_id", cmd.CommandID, "reason", cmd.Reason)

	switch cmd.Command {
	case "restart_service":
		slog.Warn("restart command — exiting for supervisor restart", "command_id", cmd.CommandID)
		c.reportCommandResult(cmd.CommandID, true, "restarting")
		// 退出让 PID1 supervisor（容器 entrypoint / systemd）重新拉起 agent。
		c.Close()
		os.Exit(0)
	case "reload_config", "sync_rules":
		err := c.apply.Reload(ctx)
		if err != nil {
			slog.Error("reload failed", "command", cmd.Command, "error", err)
			c.reportCommandResult(cmd.CommandID, false, err.Error())
		} else {
			slog.Info("reload ok", "command", cmd.Command)
			c.reportCommandResult(cmd.CommandID, true, "reloaded")
		}
	default:
		slog.Warn("unknown command", "command", cmd.Command)
		c.reportCommandResult(cmd.CommandID, false, "unknown command")
	}
}

// reportCommandResult 借用 ReportDeployResult 把命令执行结果回报 control（best-effort）。
func (c *Client) reportCommandResult(commandID string, success bool, message string) {
	rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.agent.ReportDeployResult(rctx, &pb.DeployResult{
		NodeId:    c.cfg.Agent.NodeID,
		Version:   commandID,
		Type:      "command",
		Success:   success,
		Message:   message,
		AppliedAt: timestamppb.Now(),
	})
	if err != nil {
		slog.Debug("report command result failed", "error", err)
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sendHeartbeat(ctx)
		}
	}
}

func (c *Client) sendHeartbeat(ctx context.Context) {
	metrics := collectMetrics()

	// 从 nginx stub_status 抓真实 RPS / 活动连接（配了 status_url 才采）。
	rps := c.sampleRPS(metrics)

	req := &pb.HeartbeatRequest{
		NodeId:    c.cfg.Agent.NodeID,
		Status:    &pb.NodeStatus{State: pb.NodeStatus_HEALTHY, RequestsPerSecond: rps},
		Resources: metrics,
	}

	if _, err := c.agent.Heartbeat(ctx, req); err != nil {
		slog.Warn("heartbeat failed", "error", err)
	}

	// REST 上报：当 reporter 启用 + 配置里给了 site_id 时，同步推一份 SiteMetrics
	if c.report != nil && len(c.cfg.Agent.SiteIDs) > 0 {
		for _, sid := range c.cfg.Agent.SiteIDs {
			c.report.PushSiteMetrics(sid, reporter.SiteMetricsPayload{
				RPS:              float64(rps),
				BlockedRate:      0, // 未来由 modsec/awesomerule 计算
				InstanceLabel:    c.cfg.Agent.Hostname,
				MetricsUpdatedAt: time.Now(),
			})
		}
	}
}

// sampleRPS 抓 nginx stub_status，把活动连接写进 metrics，并用两次采样的
// 累计请求差 / 时间差算 RPS。首次采样或未配 status_url 时返回 0。
func (c *Client) sampleRPS(metrics *pb.ResourceUsage) int64 {
	if c.cfg.Nginx.StatusURL == "" {
		return 0
	}
	st, err := scrapeNginxStatus(c.cfg.Nginx.StatusURL)
	if err != nil {
		slog.Debug("nginx status scrape failed", "error", err)
		return 0
	}
	metrics.NetConnections = st.ActiveConnections

	now := time.Now()
	var rps int64
	// 仅当有上次样本、且计数未回绕（nginx 重启会清零）时才算速率。
	if !c.prevSampleAt.IsZero() && st.TotalRequests >= c.prevRequests {
		elapsed := now.Sub(c.prevSampleAt).Seconds()
		if elapsed > 0 {
			rps = int64(float64(st.TotalRequests-c.prevRequests) / elapsed)
		}
	}
	c.prevRequests = st.TotalRequests
	c.prevSampleAt = now
	metrics.RequestsPerSecond = rps
	return rps
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func loadTLS(caCertPath string) (credentials.TransportCredentials, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	}), nil
}

func getLocalIP() string {
	hostname, _ := os.Hostname()
	return hostname
}
