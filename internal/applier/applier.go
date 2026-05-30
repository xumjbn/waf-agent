package applier

import (
	"context"

	"github.com/waf-agent/internal/config"
)

type Applier struct {
	Nginx  *NginxApplier
	Modsec *ModsecApplier
}

func New(cfg *config.Config) *Applier {
	return &Applier{
		Nginx:  NewNginxApplier(cfg),
		Modsec: NewModsecApplier(cfg),
	}
}

func (a *Applier) ApplyNginx(ctx context.Context, domain string, payload []byte) error {
	return a.Nginx.Apply(ctx, domain, payload)
}

func (a *Applier) ApplyModsec(ctx context.Context, domain string, payload []byte) error {
	return a.Modsec.Apply(ctx, domain, payload)
}

// Reload 触发 nginx 重载配置（reload_config / sync_rules 命令用）。
// 不重启进程，只让 nginx 重读磁盘上的配置 + 规则。
func (a *Applier) Reload(ctx context.Context) error {
	return a.Nginx.reload()
}
