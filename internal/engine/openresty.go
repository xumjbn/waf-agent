package engine

import (
	"context"

	"github.com/waf-agent/internal/config"
)

// OpenRestyEngine 是 OpenResty（NGINX + LuaJIT）引擎。OpenResty 在配置语法、
// reload 命令、stub_status 指标、ModSecurity 兼容性上与 NGINX 基本一致，
// 故复用 NginxEngine 的配置下发 / 指标 / 审计解析；区别在于：
//   - 二进制是 openresty（通过 agent.toml 的 [nginx].reload_cmd/test_cmd 配置成
//     `openresty -s reload` / `openresty -t`）；
//   - 策略下发可走 Lua WAF（lua-resty-waf 等）而非 ModSec —— 预留 hook，
//     当前默认仍走 ModSec（与 nginx 一致），待 Lua 检测落地再覆盖 ApplyPolicy。
type OpenRestyEngine struct {
	*NginxEngine
}

func NewOpenRestyEngine(cfg *config.Config) *OpenRestyEngine {
	base := NewNginxEngine(cfg)
	base.name = "openresty"
	return &OpenRestyEngine{NginxEngine: base}
}

// ApplyPolicy —— OpenResty 下可用 Lua WAF 检测。当前复用 NginxEngine（ModSec）。
// 待接入 lua-resty-waf 规则下发时在此覆盖。
func (e *OpenRestyEngine) ApplyPolicy(ctx context.Context, domain string, payload []byte) error {
	// TODO(lua-waf): OpenResty 专用 Lua 规则下发。当前与 nginx 一致走 ModSec。
	return e.NginxEngine.ApplyPolicy(ctx, domain, payload)
}
