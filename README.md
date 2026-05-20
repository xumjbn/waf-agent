# waf-agent

OpenWAF / NebulaWAF 节点 sidecar —— Go 1.22，跑在每台 nginx + ModSecurity 防护节点上。

职责：

1. **gRPC 长连接**到 waf-control：register / heartbeat / 监听 config push / 上报部署结果
2. **本地落配**：拿到 control 推下来的 nginx / modsec 配置，写文件 → `nginx -t` → `nginx -s reload`
3. **REST 上报**（与 waf-control feat/backend-\* 系列对接）：攻击日志、策略命中计数、节点指标

```
   ┌─ gRPC ─────────────────────┐    ┌─ REST ────────────────────┐
   │ register / heartbeat       │    │ POST /logs/attack         │
   │ PushConfig (server stream) │    │ POST /policies/{id}/hit   │
   │ ReportDeployResult         │    │ PUT  /sites/{id}/metrics  │
   └───────────────────────────-┘    └──────────────────────────-┘
              │                                  │
              ▼                                  ▼
                       waf-control
                            │
                   PostgreSQL + waf-admin UI
```

## 技术栈

- Go 1.22（vendored）
- grpc-go（与 waf-control 通信，proto 由 waf-control 提供，通过 `replace` 本地引用）
- spf13/viper（TOML 配置）
- shirou/gopsutil/v3（采集 CPU/内存/磁盘/网络指标）

## 目录结构

```
cmd/agent/                 # main.go：装配 grpcclient + reporter，捕获 SIGINT/SIGTERM
configs/agent.toml         # 默认配置模板
internal/
├── config/                # viper 装载 + 默认值
├── applier/               # nginx / modsec 配置落地（写文件 → test → reload）
├── grpcclient/            # 与 waf-control 的 gRPC 会话（register/heartbeat/config push）
└── reporter/              # 周期性 REST 上报（攻击日志 / 命中计数 / 站点指标）
```

## 配置（configs/agent.toml）

```toml
[agent]
node_id   = "node-01"
hostname  = "waf-node-01"
data_dir  = "/var/lib/waf-agent"
site_ids  = [1, 2]                  # 该节点接管的站点 ID，用于 PUT /sites/{id}/metrics

[server]
address               = "localhost:50051"   # waf-control gRPC 地址
tls_enabled           = false
tls_ca_cert           = ""
reconnect_backoff_sec = 5

[nginx]
config_dir     = "/etc/nginx/conf.d"
modsec_dir     = "/etc/modsecurity.d"
ssl_dir        = "/etc/nginx/ssl"
reload_cmd     = "nginx -s reload"
test_cmd       = "nginx -t"
backup_enabled = true

[collector]
interval_sec = 10                   # heartbeat & reporter flush 周期

[reporter]
enabled    = true
base_url   = "http://control.local:9200"  # waf-control REST 入口
auth_token = "<管理员签发的静态 token>"     # Bearer 鉴权
```

## 快速开始

```bash
# 1. 编译
go build -o bin/waf-agent ./cmd/agent

# 2. 跑（默认读 configs/agent.toml）
./bin/waf-agent --config configs/agent.toml
```

systemd unit 示例：

```ini
[Unit]
Description=OpenWAF Agent
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/waf-agent/bin/waf-agent --config /etc/waf-agent/agent.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 工作流程

1. **启动** → 加载 config → 装 logger
2. **gRPC 会话**（grpcclient.Run，无限重连）：
   - `Register(node_id, hostname, ip, version)` → 拿到 `assigned_id` + `heartbeat_interval`
   - 起 heartbeat goroutine：采 CPU/MEM/磁盘/网络，定时 `Heartbeat(...)`；如果 reporter 启用并配了 site_id，同时 `PUT /sites/{id}/metrics`
   - 起 config 流：`PushConfig(...)` server-stream → 收到 SITE/POLICY/FULL 配置 → 调 applier 落盘 → `ReportDeployResult(...)`
3. **REST 上报**（reporter.Run，每 `collector.interval_sec` 触发一次 flush）：
   - `attackQueue` → `POST /api/v1/logs/attack`
   - `hitQueue`（policyID → delta）→ `POST /api/v1/policies/{id}/hit`
   - `siteQueue`（siteID → metrics）→ `PUT /api/v1/sites/{id}/metrics`

## 上报哪些字段

`AttackLogPayload` 与 waf-control `internal/domain/logs.AttackLog` 完全对齐（migration 000011 起的 UI 富字段）：基础五元组 + `region/country/lat/lng/site/domain/type_label/type_color/risk/method/uri/user_agent`。

`SiteMetricsPayload` 对齐 `internal/domain/site.UpdateMetricsRequest`：`rps / blocked_rate / instance_label / metrics_updated_at`。

> 当前 RPS / BlockedRate 是占位 0，等接 nginx access_log + modsec audit 后补真值。

## 仓库归属

`waf-agent` 是 OpenWAF monorepo（[xumjbn/OpenWAF](https://github.com/xumjbn/OpenWAF)）下的 git 子模块。
go.mod 里通过 `replace github.com/waf-control => ../waf-control` 本地复用 control 的 proto 与共享类型 —— monorepo 内开发不需要单独发版。
