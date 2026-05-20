package grpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
)

type Client struct {
	cfg    *config.Config
	conn   *grpc.ClientConn
	agent  pb.AgentServiceClient
	apply  ConfigApplier
	report *reporter.Reporter // 可空：REST 上报器
}

// AttachReporter 让 grpcclient 把心跳采集到的 ResourceUsage 同步推给 REST reporter。
func (c *Client) AttachReporter(r *reporter.Reporter) {
	c.report = r
}

type ConfigApplier interface {
	ApplyNginx(ctx context.Context, domain string, payload []byte) error
	ApplyModsec(ctx context.Context, domain string, payload []byte) error
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

	// RPS 计算占位（未来由 nginx access_log / modsec hits 抽取）；先用 0 表示未知。
	const rpsPlaceholder int64 = 0

	req := &pb.HeartbeatRequest{
		NodeId:    c.cfg.Agent.NodeID,
		Status:    &pb.NodeStatus{State: pb.NodeStatus_HEALTHY, RequestsPerSecond: rpsPlaceholder},
		Resources: metrics,
	}

	if _, err := c.agent.Heartbeat(ctx, req); err != nil {
		slog.Warn("heartbeat failed", "error", err)
	}

	// REST 上报：当 reporter 启用 + 配置里给了 site_id 时，同步推一份 SiteMetrics
	if c.report != nil && len(c.cfg.Agent.SiteIDs) > 0 {
		for _, sid := range c.cfg.Agent.SiteIDs {
			c.report.PushSiteMetrics(sid, reporter.SiteMetricsPayload{
				RPS:              float64(rpsPlaceholder),
				BlockedRate:      0, // 未来由 modsec/awesomerule 计算
				InstanceLabel:    c.cfg.Agent.Hostname,
				MetricsUpdatedAt: time.Now(),
			})
		}
	}
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
