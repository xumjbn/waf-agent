package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/waf-agent/internal/applier"
	"github.com/waf-agent/internal/config"
	"github.com/waf-agent/internal/grpcclient"
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

	slog.Info("waf-agent starting", "hostname", cfg.Agent.Hostname)

	app := applier.New(cfg)
	client := grpcclient.New(cfg, app)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := client.Run(ctx); err != nil {
			slog.Error("client run error", "error", err)
		}
	}()

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
