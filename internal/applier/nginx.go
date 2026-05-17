package applier

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/waf-agent/internal/config"
)

type NginxApplier struct {
	cfg *config.Config
}

func NewNginxApplier(cfg *config.Config) *NginxApplier {
	return &NginxApplier{cfg: cfg}
}

func (a *NginxApplier) Apply(ctx context.Context, domain string, payload []byte) error {
	if domain == "" || domain == "default" {
		domain = extractDomain(payload)
	}
	if domain == "" {
		return fmt.Errorf("could not determine domain from config")
	}

	slog.Info("applying nginx config", "domain", domain)

	cfgPath := filepath.Join(a.cfg.Nginx.ConfigDir, domain+".conf")

	// Backup existing config
	if a.cfg.Nginx.BackupEnabled {
		if data, err := os.ReadFile(cfgPath); err == nil {
			bakPath := cfgPath + ".bak"
			if err := os.WriteFile(bakPath, data, 0644); err != nil {
				slog.Warn("backup nginx config failed", "path", bakPath, "error", err)
			}
		}
	}

	// Atomic write: write to temp file then rename
	tmpPath := cfgPath + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0644); err != nil {
		return fmt.Errorf("write nginx config: %w", err)
	}
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename nginx config: %w", err)
	}

	// Validate and reload
	if err := a.test(); err != nil {
		// Restore backup
		if a.cfg.Nginx.BackupEnabled {
			bakPath := cfgPath + ".bak"
			if data, err := os.ReadFile(bakPath); err == nil {
				os.WriteFile(cfgPath, data, 0644)
				_ = a.test() // try to restore working config
			}
		}
		return fmt.Errorf("nginx test failed: %w", err)
	}

	if err := a.reload(); err != nil {
		return fmt.Errorf("nginx reload failed: %w", err)
	}

	return nil
}

func (a *NginxApplier) test() error {
	cmd := exec.Command("sh", "-c", a.cfg.Nginx.TestCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), string(out))
	}
	return nil
}

func (a *NginxApplier) reload() error {
	cmd := exec.Command("sh", "-c", a.cfg.Nginx.ReloadCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err.Error(), string(out))
	}
	return nil
}

func extractDomain(payload []byte) string {
	content := string(payload)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "server_name") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				domain := strings.TrimSuffix(fields[1], ";")
				if domain != "_" {
					return domain
				}
			}
		}
	}
	return "unknown"
}
