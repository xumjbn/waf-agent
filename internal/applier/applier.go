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
