# LightPN 项目规划书

**版本** v0.2 · 2026-07 · 状态:早期可运行原型,正在进行多节点部署与稳定性测试

---

## 1. 项目概述

LightPN(Light Private Network)是一套极简的 WireGuard 网络编排系统,采用星形控制拓扑:一个中心节点(hub)负责节点准入、连接撮合与状态监控;若干边缘节点(agent)在 hub 的指挥下建立点对点的 WireGuard 隧道。数据面流量完全点对点直连,不经过中心。

项目的直接动机是替代 NetBird 一类的全功能 overlay 网络方案。NetBird/Tailscale 的复杂度大部分花在 NAT 穿透上——STUN/TURN/DERP 中继、ICE 协商、打洞状态机——而 LightPN 的目标环境是全部拥有公网地址、可直接互连的服务器,这些组件可以整体砍掉。剩下的核心问题只有三个:节点如何安全加入、连接关系如何集中管理、节点状态如何被看见。LightPN 就只解决这三个问题。

整套系统由两个静态编译的 Go 二进制组成。`lightpn-hub` 运行在中心节点,内含撮合服务、指标收集与一个内嵌的 Web 控制面板;`lightpn-agent` 运行在每个边缘节点,负责维持控制通道、按指令操作内核 WireGuard、随心跳上报系统指标。没有外部数据库,没有容器依赖,没有第三方监控组件。

### 与现有方案的定位对比

| | NetBird / Tailscale | Headscale | LightPN |
|---|---|---|---|
| NAT 穿透 / 中继 | 有(主要复杂度来源) | 有 | 无(目标环境不需要) |
| 数据面 | P2P + 中继兜底 | P2P + DERP | 纯 P2P |
| 边缘配置持久化 | 有 | 有 | 无(peer 全内存,WG 密钥 ephemeral) |
| 监控 | 需另配 | 需另配 | 内建(心跳携带指标) |
| 组件数 | 多进程 + 数据库 | 单进程 + 数据库 | hub/agent 各一个二进制 |
| 目标规模 | 数千节点 | 数百节点 | 数十节点,1C1G 可跑 |

---

## 2. 目标与非目标

**目标**

1. 边缘节点之间的 WireGuard 连接**必须且只能**经 hub 撮合建立;边缘节点不持有、不落盘任何 peer 配置。
2. 提供 Web 控制面板,支持节点的添加(一次性 token 入网)、删除(级联清理)、连接关系(link)的增删,以及全网节点的实时状态与历史指标曲线。
3. 监控能力内建于控制通道,不引入 Beszel 等外部监控组件。
4. 整套 hub 侧服务(含 cloudflared)在 1 vCPU / 1 GB RAM 的 VPS 上稳定运行,常态内存占用 < 100 MB。
5. 控制面板经 Cloudflare Tunnel 暴露,面板端口不出现在公网。

**非目标(明确不做)**

- NAT 打洞、UDP 中继、ICE:目标环境全部公网直连。
- 多租户、RBAC、审计日志:单管理员起步。
- 移动端/桌面端客户端:节点均为 Linux 服务器。
- ACL/子网路由/通用三层 exit node 等高级路由功能:overlay 内只做 /32 点对点。当前仅提供基于 overlay 可达 SOCKS5 服务的轻量出口选择(见 README「链式出口」),不是全局默认路由出口。
- 高可用 hub:hub 短暂宕机不影响已建立的数据面隧道(见 §4 不变量 1),单点可接受。

---

## 3. 总体架构

```
                        ┌────────────────────────────────────────┐
                        │           中心节点 (1C1G VPS)           │
                        │                                        │
   Cloudflare Tunnel ───┼─▶ 127.0.0.1:7441  Web 面板 + REST/WS   │
   (管理员浏览器)        │            lightpn-hub                 │
                        │   0.0.0.0:7440  控制通道 (mTLS)  ◀─────┼──┐
                        │   [SQLite: 节点表/link/token/账号]      │  │
                        │   [内存: 指标 ring buffer/在线会话]      │  │
                        └────────────────────────────────────────┘  │
                                                                    │ 控制通道(长连接)
              ┌─────────────────────────┬──────────────────────────┤ 撮合/心跳/管理指令
              ▼                         ▼                          ▼
      ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
      │ lightpn-agent │          │ lightpn-agent │          │ lightpn-agent │
      │ 边缘节点 A     │◀════════▶│ 边缘节点 B    │◀════════▶│ 边缘节点 C    │
      └──────────────┘  WG 直连  └──────────────┘  WG 直连  └──────────────┘
                        (数据面,不经中心)
```

**组件职责**

hub 承担四件事:节点准入(签发/吊销身份证书)、IPAM(overlay 地址分配)、撮合(维护 link 配置并向双方推送 peer 信息)、观测(收集心跳、驱动面板)。agent 承担三件事:维持到 hub 的 mTLS 长连接、经 wgctrl 操作内核 WireGuard 设备(创建接口、注入/移除 peer)、采集并上报系统指标(gopsutil)。

**关键数据流**

- 撮合流:面板创建 link → hub 同时向 A、B 推送对方的 `(pubkey, endpoint, allowed_ips)` → 两侧注入内核 → WG 自行握手 → hub 从后续心跳中的握手时间戳确认 link 生效。
- 监控流:agent 心跳(15s)携带系统指标与本机 WG peer 状态 → hub 写入内存 ring buffer → 经 WebSocket 扇出给在线的面板会话。

---

## 4. 设计不变量

以下五条是全部设计决策的根,任何后续改动不得违反:

1. **数据面独立于控制面。** WG 流量永远点对点,控制通道断连、hub 重启均不得中断已建立的隧道。由此推出:节点掉线不立即撤对端 peer(见 §5.6)。
2. **边缘零连接记录。** agent 不落盘任何 peer 配置;WG 私钥每次进程启动时现场生成,只存在于进程内存与内核设备中。agent 唯一的持久化文件是自己的身份证书与身份私钥(这是"我是谁",不是"我连过谁")。
3. **撮合强制经 hub。** 边缘节点没有任何途径获知其他节点的 WG 公钥与 endpoint;WireGuard 拒绝未配置 peer 的握手,这条约束由密码学而非策略保证。
4. **hub 最小持久化。** SQLite 只存节点注册表、IP 分配、link 配置与管理员账号;不存指标历史(内存 ring buffer)、不存任何 WG 私钥、不存连接历史。
5. **endpoint 不可自报。** 撮合下发的节点公网 IP 取自其控制通道 TCP 连接的源地址,agent 只能声明 WG 监听端口,防止伪造 endpoint 劫持流量。

---

## 5. 控制通道协议

### 5.1 传输层

控制通道运行在 TCP 之上,hub 监听公网 `:7440`(可配置)。加密与双向认证采用 mTLS:hub 首次启动时生成一个自签 CA(私钥存于 hub 数据目录,权限 0600),hub 的服务端证书与所有 agent 的客户端证书均由该 CA 签发。agent 侧在 enrollment 时记录 CA 指纹(TOFU 加固),此后每次连接校验;hub 侧以客户端证书的 CN 字段(= NodeID)完成节点认证,另维护内存吊销名单拒绝已删除节点。

消息帧为 **4 字节大端长度前缀 + JSON**,单帧上限 1 MiB。所有消息共享统一信封:

```json
{
  "v": 1,              // 协议版本,不兼容变更时递增
  "type": "heartbeat", // 消息类型,见附录 A 速查表
  "id": "01J8KQ...",   // ULID;请求/响应经 id 关联,推送类消息亦携带以便 ACK 与日志追踪
  "data": { }
}
```

存活机制:agent 每 15 秒发送一次心跳,hub 连续 45 秒未收到即标记该节点 `offline` 并关闭连接;agent 断线后以指数退避重连(初始 1s,上限 60s,±20% 抖动防惊群)。

### 5.2 Enrollment(节点入网)

入网是一次性流程,产物是 agent 的客户端证书,此后所有会话凭证书认证,token 不再出现。

流程:管理员在面板生成一次性 token(默认 TTL 15 分钟,使用即焚)→ 在边缘机器执行 `lightpn-agent enroll --hub <ip>:7440 --token <token>`。agent 以仅服务端认证的 TLS 连接 hub 并发送:

```json
{ "v":1, "type":"enroll", "id":"...", "data": {
    "token": "lp_xxxxxxxxxxxx",
    "hostname": "edge-tokyo-1",
    "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."
}}
```

身份密钥对由 agent 现场生成,私钥不出机器,hub 只见 CSR。hub 校验 token 后分配 NodeID(ULID)与 overlay IP,签发客户端证书(CN=NodeID,有效期 1 年,支持在线轮换),返回:

```json
{ "v":1, "type":"enroll_ack", "id":"...", "data": {
    "node_id": "01J8KQZC...",
    "cert_pem": "...",
    "ca_pem": "...",
    "overlay_ip": "100.100.0.7/32",
    "overlay_cidr": "100.100.0.0/24",
    "control_addr": "203.0.113.10:7440"
}}
```

agent 将证书与身份私钥写入 `/var/lib/lightpn/identity/`(全系统唯一的持久化文件),随即断开并以 mTLS 重连进入正常会话。

### 5.3 会话注册(register)

每次 mTLS 连接建立后,agent 首先声明本次运行的 ephemeral WireGuard 材料:

```json
{ "v":1, "type":"register", "id":"...", "data": {
    "wg_pubkey": "base64...",   // 本次进程启动时现场生成
    "wg_port": 51820,           // agent 实际监听的 WG 端口(唯一可自报项)
    "agent_version": "0.1.0",
    "os": "linux/amd64"
}}
```

hub 回复 `register_ack`,其中携带该节点当前**应有的全量 peer 清单** `peers_expected`。agent 以此为准做一次全量对账:移除内核中多余的 peer、补齐缺失的 peer,之后的增量推送在此基线上生效。这一对账机制保证任意一侧重启后系统都能收敛到正确状态,不依赖"消息不丢"的假设。

由于 WG 密钥是 ephemeral 的,agent 每次重启后公钥必然改变,hub 在处理 register 时必须同时向所有与之存在 link 的在线对端推送 `peer_update`(携带新公钥),对端隧道在一个推送周期内恢复。**这是全协议最容易出一致性 bug 的路径,实现与测试须重点覆盖**(测试矩阵见 §12)。

### 5.4 心跳(heartbeat)

```json
{ "v":1, "type":"heartbeat", "id":"...", "data": {
    "ts": 1783000000,
    "sys": {
      "cpu_pct": 12.5, "load1": 0.30,
      "mem_used": 412000000,  "mem_total": 1024000000,
      "disk_used": 9800000000, "disk_total": 25000000000,
      "net_rx_bytes": 123456789, "net_tx_bytes": 987654321,
      "uptime_s": 86400
    },
    "wg": [
      { "peer_node_id": "01J9A...",
        "last_handshake_ts": 1782999980,
        "rx_bytes": 10240, "tx_bytes": 20480,
        "endpoint": "198.51.100.5:51820" }
    ]
}}
```

`net_*_bytes` 为累计计数器,由 hub 差分求速率。`wg[]` 段使 hub 无需任何额外探测即可绘制连接矩阵、判断撮合是否真正完成握手。hub 侧每节点维护 24 小时 × 30 秒粒度的内存 ring buffer(约 2880 采样点,每点不足 200 字节;50 节点合计约 30 MB)。

### 5.5 撮合与 peer 生命周期

连接意图(link)由 hub 权威管理,唯一来源是面板操作;agent 只被动执行推送,协议信封中已预留 agent 主动请求撮合的消息类型但 v0 不实现。hub → agent 的三条推送:

```json
{ "v":1, "type":"peer_add", "id":"...", "data": {
    "link_id": "01JA...",
    "peer_node_id": "01J9A...",
    "peer_name": "edge-osaka-1",
    "wg_pubkey": "base64...",
    "endpoint": "198.51.100.5:51820",
    "allowed_ips": ["100.100.0.9/32"],
    "keepalive_s": 25
}}

{ "v":1, "type":"peer_remove", "id":"...", "data": {
    "link_id": "01JA...", "wg_pubkey": "base64..." }}

{ "v":1, "type":"peer_update", "id":"...", "data": { /* 字段同 peer_add,语义为覆盖 */ }}
```

agent 执行后统一回执:

```json
{ "v":1, "type":"ack", "id":"<对应推送的 id>", "data": { "ok": true, "err": "" } }
```

### 5.6 掉线与回收策略

节点 `offline`(控制通道断)不立即撤除对端 peer——数据面可能仍在正常运行,控制面抖动不应波及。offline 持续超过 `peer_gc_after`(默认 5 分钟)后,hub 才向相关对端推送 `peer_remove`;节点重新 register 后按新公钥重新撮合。此参数与心跳周期、重连退避共同构成系统的时间常数,集中定义于 hub 配置文件。

### 5.7 管理指令与错误

```json
{ "type":"kick",        "data": { "reason": "removed by admin" } }
    // agent:清空全部内核 peer → 删除身份文件 → 进程退出。保证被删节点不残留任何记录。
{ "type":"rotate_wg",   "data": {} }
    // agent:重新生成 WG 密钥并重新 register(复用 §5.3 的收敛路径)
{ "type":"rotate_cert", "data": { "cert_pem": "..." } }
    // 证书在线续期
```

错误消息统一为 `{ "type":"error", "data":{ "code":"...", "msg":"..." } }`,首批错误码:`TOKEN_EXPIRED` / `TOKEN_USED` / `AUTH_FAILED` / `CERT_REVOKED` / `VERSION_UNSUPPORTED` / `IPAM_EXHAUSTED` / `UNKNOWN_TYPE` / `INTERNAL`。

---

## 6. Hub 管理 API

管理 API 与面板静态资源由 hub 内嵌提供,监听 `127.0.0.1:7441`,仅经 Cloudflare Tunnel 暴露,公网不可达。所有接口位于 session 认证之后;若启用 Cloudflare Access,hub 额外校验 `Cf-Access-Jwt-Assertion` 头,形成双层认证。

### 6.1 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{username, password}` → 设置 HttpOnly + SameSite=Strict 的 session cookie |
| POST | `/api/logout` | 销毁 session |

管理员密码以 argon2id 哈希存储,由 `lightpn-hub admin set-password` 在部署时初始化。登录接口做速率限制(每 IP 每分钟 5 次)。

### 6.2 节点管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/nodes` | 节点列表:`[{id, name, overlay_ip, status, endpoint, agent_version, last_seen, sys_summary}]`,status ∈ online / offline / stale |
| GET | `/api/nodes/{id}` | 节点详情,含最近心跳中的完整 peer 表 |
| GET | `/api/nodes/{id}/metrics?range=1h&step=30s` | 时序数据:`{ts[], cpu[], mem[], rx_rate[], tx_rate[], disk[]}` |
| GET | `/api/nodes/{id}/toolconf` | 经控制通道实时向 agent 请求(`conf_get`)其 WG 运行时状态与翻墙软件配置;不缓存不落盘,节点离线 409、agent 超时未答 504 |
| PATCH | `/api/nodes/{id}` | 修改备注名 |
| DELETE | `/api/nodes/{id}` | 级联删除,顺序:删除该节点全部 link → 向各对端推 `peer_remove` → 向该节点推 `kick` → 证书序列号入吊销名单 → overlay IP 进入冷却池 |

### 6.3 入网 token

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/tokens` | `{ttl_s?, note?}` → `{token, expires_at}`。完整 token 仅此一次返回,库中只存哈希 |
| GET | `/api/tokens` | 有效 token 列表(仅显示前缀与备注) |
| DELETE | `/api/tokens/{id}` | 作废 |

### 6.4 Link(连接撮合)

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/links` | `[{id, a, b, status, created_at, last_handshake, rx_rate, tx_rate}]` |
| POST | `/api/links` | `{a, b}`。双方在线则立即推送 `peer_add`;任一方离线则置 pending,其上线 register 时补推 |
| DELETE | `/api/links/{id}` | 向双方推送 `peer_remove` |

link 状态机:`pending`(已创建,至少一方未在线或未 ACK)→ `active`(双方 ACK 且任一侧心跳出现 <180s 的握手时间)→ `degraded`(双方 ACK 但持续无握手,面板高亮提示,最常见原因是 WG UDP 端口未放行)。删除即终态。

### 6.5 实时推送 `GET /api/ws`

面板加载后建立一条 WebSocket,hub 向所有在线面板会话扇出四类事件:

```json
{ "ev":"node_status", "data": { "node_id":"...", "status":"online" } }
{ "ev":"heartbeat",   "data": { "node_id":"...", "sys":{...}, "wg":[...] } }
{ "ev":"link_status", "data": { "link_id":"...", "status":"active" } }
{ "ev":"enrolled",    "data": { "node_id":"...", "name":"edge-tokyo-1" } }
```

前端的实时性完全依赖这条 WS;REST 仅用于首屏快照与写操作。WS 断线后前端自动重连并重拉快照。

---

## 7. Web 控制面板

技术选型延续"不臃肿"基调:Preact + uPlot(合计 gzip 后 < 50 KB),Vite 构建,产物经 `go:embed` 打入 hub 二进制——部署物仍是单个可执行文件,无 Node、无 Nginx、无静态目录。

三个核心页面:

1. **节点总览**:卡片/表格双视图。每节点展示在线状态、overlay IP、CPU/内存迷你火花线、实时收发速率;操作项为改名、生成删除确认、跳转详情。页面顶部常驻"添加节点"按钮,点击即生成 token 并展示可复制的一行入网命令。
2. **节点详情**:24h 指标曲线(CPU / 内存 / 磁盘 / 网卡速率,uPlot 渲染),下方为该节点当前 peer 表(对端名称、最近握手、累计流量)与该节点的操作区(轮换 WG 密钥、踢下线、删除)。
3. **连接矩阵**:全网节点的 N×N 矩阵或列表视图,呈现每条 link 的状态与实时速率;单元格点击即可创建/删除 link。`degraded` 状态以醒目颜色提示并附排障提示文案。

面板不展示、不传输任何私钥材料——WG 私钥只活在 agent 内存,身份私钥不出边缘机器,这一点与"CF Tunnel 会在边缘终结 TLS"的现实相容:即使 Cloudflare 可见面板明文,可见的也只有指标与管理操作。

---

## 8. IPAM 与数据模型

overlay 网段默认 `100.100.0.0/24`(可配置,建议保持在 CGNAT 段 100.64.0.0/10 内以避免与常见内网冲突)。地址分配与 NodeID 绑定并持久化;节点删除后其 IP 进入 30 天冷却池后方可复用,避免残留路由串扰。`.0`、`.255` 不分配,`.1` 预留给未来可能加入 overlay 的 hub 自身。

hub 的 SQLite schema(纯 Go 驱动 `modernc.org/sqlite`,免 CGO,交叉编译友好):

```sql
CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,        -- ULID
  name        TEXT NOT NULL,
  overlay_ip  TEXT NOT NULL UNIQUE,
  cert_serial TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER,
  revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE links (
  id          TEXT PRIMARY KEY,
  a           TEXT NOT NULL REFERENCES nodes(id),
  b           TEXT NOT NULL REFERENCES nodes(id),
  created_at  INTEGER NOT NULL,
  UNIQUE(a, b)                          -- 存储前对 (a,b) 排序去重
);
CREATE TABLE tokens (
  id          TEXT PRIMARY KEY,
  hash        TEXT NOT NULL,            -- token 的 SHA-256,明文不落库
  note        TEXT,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE TABLE admins (
  id          TEXT PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  pw_hash     TEXT NOT NULL             -- argon2id
);
CREATE TABLE ip_cooldown (
  overlay_ip  TEXT PRIMARY KEY,
  freed_at    INTEGER NOT NULL
);
-- 指标不入库(内存 ring buffer)。如未来需要长期历史,
-- 增加按 5 分钟降采样的可选 metrics 表,默认关闭。
```

---

## 9. 安全设计

**密钥体系分三层,互不混用:**

| 层 | 材料 | 生命周期 | 存放 |
|---|---|---|---|
| 信任根 | hub CA 密钥对 | 长期 | hub 数据目录,0600 |
| 节点身份 | agent 身份密钥 + 客户端证书 | 1 年,可在线轮换 | agent `/var/lib/lightpn/identity/` |
| 数据面 | WG 密钥对 | 单次进程生命周期 | 仅 agent 内存与内核设备 |

身份与数据面分离的直接收益:WG 密钥可以随意轮换乃至每次重启即换,而节点身份保持稳定;吊销身份证书即彻底逐出节点,无需触碰任何 WG 配置。

**面板暴露面**:面板端口只绑 127.0.0.1,由 cloudflared 拉出,公网扫描不可见。认证共三层——Cloudflare Access(可选但推荐,email OTP 或 OAuth)、hub 自身 session 登录、登录接口速率限制。需要清醒认识的一点是 Cloudflare 在其边缘终结 TLS,能够看到面板明文流量;设计上以"面板永不接触私钥材料"来消化这一暴露,而控制通道(mTLS)与数据面(WG)均不经过 Cloudflare,不受影响。

**控制通道暴露面**:7440 端口直接暴露公网,但 TLS 握手要求客户端证书,无证书的连接在握手阶段即被拒绝,应用层代码不可达;enrollment 例外路径仅接受一条 `enroll` 消息且受 token 与速率限制约束。被删除节点的证书序列号进入内存吊销名单(启动时从 SQLite 重建),即使证书未过期也无法再连。

**威胁模型内不防御的项**(诚实列出):hub 被完全攻陷(攻陷者可向任意节点推送任意 peer,即获得对 overlay 的中间人能力——这是星形撮合架构的固有信任假设);Cloudflare 作恶;边缘节点 root 被攻陷。

---

## 10. 部署与运维

**hub 侧**(1C1G VPS):`lightpn-hub` + `cloudflared` 两个 systemd 服务。防火墙放行:7440/tcp(控制通道)、可选 51820/udp(若 hub 未来加入 overlay);7441 不放行。资源预算:hub 进程 30–50 MB,cloudflared 约 30 MB,SQLite 与 ring buffer 合计 < 50 MB,总占用不足 1 GB 的一半,余量充足。

**agent 侧**:单 systemd 服务,`After=network-online.target`。依赖内核 WireGuard 模块(Linux ≥ 5.6 内置);防火墙放行本机 WG UDP 端口(默认 51820,`--wg-port <N>` 可改)。因 endpoint 端口取自 agent 自报值(不变式 5,§4)、IP 取自控制连接源,自定义端口须保证 `<公网IP>:<N>` 公网可达且不落在做端口转换的 NAT 后(外部端口须等于自报端口),否则对端会打到错误 endpoint、link 停在 `degraded`。agent 崩溃或重启的恢复完全走 §5.3 的 register 收敛路径,无需人工干预。

**升级策略**:协议信封的 `v` 字段 + register 中的 `agent_version` 支撑灰度:hub 兼容 N 与 N-1 两个协议版本,agent 逐台升级。hub 自身升级导致的控制通道中断不影响数据面(不变量 1),窗口期内仅撮合与监控不可用。

**备份**:唯一需要备份的状态是 hub 数据目录(SQLite + CA 密钥),一个 cron tar 即可。CA 丢失意味着全网重新 enrollment,务必纳入备份。

---

## 11. 开发路线图

| 里程碑 | 内容 | 验收标准 | 预估 |
|---|---|---|---|
| **M0 骨架** | hub:mTLS 监听、消息路由、SQLite、CA 与 enrollment 全流程;agent:enroll 子命令、身份持久化、mTLS 重连 | 一台新机器凭 token 一条命令入网,面板 API(curl)可见节点在线 | 1 周 |
| **M1 撮合** | register/对账、wgctrl 注入、peer_add/remove/update、link 状态机、掉线 GC | 面板 API 创建 link 后两节点 overlay IP 互 ping 通;任一 agent 重启后 30s 内隧道自愈 | 1 周 |
| **M2 观测** | 心跳携带指标、ring buffer、metrics API、WS 事件扇出 | curl 可拉取任意节点 1h 曲线数据;WS 能实时收到心跳事件 | 3–4 天 |
| **M3 面板** | Preact 前端三页面、go:embed、session 认证、token/节点/link 的完整 UI 操作 | 全部管理操作可纯 UI 完成,不再需要 curl | 1–1.5 周 |
| **M4 加固** | kick 级联与证书吊销、rotate_wg/rotate_cert、速率限制、systemd 单元与部署文档、CF Tunnel 接入文档 | §12 测试矩阵全绿,写出从零到三节点的部署 runbook | 1 周 |

合计约 5–6 周的业余时间投入。代码量预估:hub 2.5–3k 行,agent 0.8–1k 行,前端 1.5k 行左右。

## 12. 风险与测试重点

最大的正确性风险集中在 **ephemeral WG 密钥 × 分布式状态收敛**:agent 重启、hub 重启、双方同时重启、推送丢失、ACK 丢失的组合都必须收敛到一致状态。M1 的验收必须覆盖如下矩阵:agent 重启(对端应在一个推送周期内拿到新公钥)、hub 重启(register 对账应纠正一切漂移)、link 创建时一方离线(上线补推)、节点删除时目标离线(上线即 kick)、同一 link 快速反复增删(以 hub 内的串行化队列避免乱序)。

次级风险:时间常数配置不当导致的"假死"体验(心跳 15s / 判死 45s / GC 5min / 退避上限 60s 需整体调校);SQLite 在低端 VPS 磁盘上的写放大(WAL 模式 + 指标不落盘已基本规避);Cloudflare Tunnel 偶发中断(只影响面板可达性,列为可接受)。

开放问题(不阻塞开发,留给 v0.2+):agent 按需撮合(ConnectRequest)是否开放及其授权模型;指标长期历史与告警(Webhook);link 的分组/标签批量操作。

---

## 附录 A:控制通道消息速查

| type | 方向 | 语义 |
|---|---|---|
| `enroll` / `enroll_ack` | A→H / H→A | 一次性入网,签发身份证书 |
| `register` / `register_ack` | A→H / H→A | 会话注册,声明 ephemeral WG 材料;ack 携带全量对账清单 |
| `heartbeat` | A→H | 15s 周期,系统指标 + 本机 WG peer 状态 |
| `peer_add` / `peer_remove` / `peer_update` | H→A | 撮合推送,agent 操作内核后回 ack |
| `ack` | A→H | 对推送的统一回执 |
| `kick` | H→A | 清 peer、毁身份、退出 |
| `rotate_wg` / `rotate_cert` | H→A | 密钥/证书轮换 |
| `conf_get` / `conf_result` | H→A / A→H | 面板触发的工具配置读取:agent 回传 WG 运行时摘要(无私钥)与翻墙软件配置文件 —— 内嵌常见路径白名单自动探测(含 caddy/naiveproxy),外加本地 `services.json` 中登记了 `conf` 路径的条目(登记项读取失败回 `Err` 便于排查;登记只能经本机 CLI,协议不接受任何下发路径)。agent 设有查看密码(`view.key`)时,payload 为「打码预览(敏感值→••,与面板 MASK_RE 同步的 maskRE 识别)+ `enc` 信封(Argon2id 派生密钥对 gzip(完整明文 JSON) 做 AES-256-GCM)」:面板先渲染预览,点击打码位才在浏览器解密;hub 只透传,看得到结构、看不到敏感值。conf_result 另携 `services`(仅设查看密码的节点):operator 登记的可远程开关服务,只含别名与状态,unit 名不上线 |
| `svc_action` / `svc_result` | H→A / A→H | 面板触发的服务开关。指令由 operator 浏览器用查看密码派生的 key 加密 `{action∈{start,stop,restart}, alias, ts}`(AES-256-GCM);hub 只转发密文,**无法伪造/篡改/重放**(agent 侧 GCM 验真 + ±5 分钟时间窗 + IV 去重)。agent 解密验真后经本地 `services.json` 把别名翻译成 unit,`systemctl <action> <unit>`(固定 argv,不经 shell)。别名→unit(+可选 conf 配置路径)映射只由本地 CLI(svc-add/svc-del)维护,hub 无任何写入途径 |
| `error` | 双向 | 统一错误,含错误码 |
