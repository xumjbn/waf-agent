package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/waf-agent/internal/auditlog"
	"github.com/waf-agent/internal/config"
	"github.com/waf-agent/internal/engine"
	"github.com/waf-agent/internal/grpcclient"
	"github.com/waf-agent/internal/reporter"
)

func main() {
	configPath := flag.String("config", "configs/agent.toml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	setupLogger()

	// 按 [engine].type 装配后端引擎（nginx / openresty / safeline），改配置重启切换。
	eng := engine.New(cfg)
	slog.Info("waf-agent starting", "hostname", cfg.Agent.Hostname, "engine", eng.Name())

	client := grpcclient.New(cfg, eng)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. gRPC 会话（register / heartbeat / config push）
	go func() {
		if err := client.Run(ctx); err != nil {
			slog.Error("client run error", "error", err)
		}
	}()

	// 2. REST 上报（攻击日志 / 命中计数 / 站点指标）— 与 waf-control feat/backend-* 对接
	if cfg.Reporter.Enabled && cfg.Reporter.BaseURL != "" {
		rep := reporter.New(cfg, cfg.Reporter.BaseURL, cfg.Reporter.AuthToken)
		client.AttachReporter(rep)
		slog.Info("reporter enabled", "base_url", cfg.Reporter.BaseURL)
		go rep.Run(ctx)

		// 3. 引擎审计日志 tailer：真实采集攻击事件上报 + 累计拦截数（算拦截率）。
		//    解析格式由引擎决定（modsec JSON / 雷池日志 / ...）。
		if eng.AuditLogPath() != "" {
			tailer := auditlog.New(eng, rep)
			go tailer.Run(ctx, cfg.Collector.IntervalSec)
			slog.Info("audit log tailer enabled", "engine", eng.Name(), "path", eng.AuditLogPath())
		} else {
			slog.Info("audit log tailer disabled — engine has no audit log path configured")
		}
	} else {
		slog.Info("reporter disabled — set [reporter].enabled=true and base_url to upload attack logs / metrics over REST")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("waf-agent shutting down")
	cancel()
}

func setupLogger() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
}
