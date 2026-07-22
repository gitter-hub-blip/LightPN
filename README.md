# LightPN

极简 WireGuard 网络编排系统:一个中心节点(hub)负责节点准入、连接撮合与状态监控,边缘节点(agent)在 hub 指挥下建立点对点 WireGuard 隧道。数据面流量完全直连,不经过中心。设计详见 [AGENT.md](AGENT.md)。

- **两个静态二进制**:`lightpn-hub`(撮合 + 监控 + 内嵌 Web 面板)、`lightpn-agent`(控制通道 + 内核 WireGuard + 指标上报)
- **无外部依赖**:无数据库进程、无 Node、无 Nginx —— SQLite 内嵌(纯 Go 驱动),前端经 `go:embed` 打入 hub 二进制
- **边缘零连接记录**:agent 不落盘任何 peer 配置,WG 私钥每次进程启动现场生成
- **监控内建**:15s 心跳携带系统指标与 WG 握手状态,面板实时曲线,不需要额外监控组件

## 构建

需要 Go ≥ 1.26(以 `go.mod` 声明为准)。纯 Go、免 CGO,可任意交叉编译:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/lightpn-hub   ./cmd/lightpn-hub
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/lightpn-agent ./cmd/lightpn-agent
```

或直接 `./deploy/build.sh`(`GOARCH=arm64` 可切架构),它会把两个二进制和对应的服务器管理脚本一起放进 `bin/`。

## 脚本化安装(推荐)

[deploy/lightpn-hub.sh](deploy/lightpn-hub.sh) 与 [deploy/lightpn-agent.sh](deploy/lightpn-agent.sh) 是**交互式菜单脚本**,内嵌了 systemd 单元,把「二进制 + 同名脚本」两个文件传到服务器即可:

```sh
# 本地
./deploy/build.sh
scp bin/lightpn-hub   bin/lightpn-hub.sh   root@hub:/root/
scp bin/lightpn-agent bin/lightpn-agent.sh root@edge:/root/

# 服务器上直接运行进入菜单,输入编号选择功能
sudo ./lightpn-hub.sh     # hub 机器
sudo ./lightpn-agent.sh   # 边缘机器
```

菜单涵盖:安装/升级、入网(agent)、启动/停止/重启、状态、日志(含实时跟踪)、重设管理员密码(hub)、完全卸载。所需参数(公网地址、入网 token、SOCKS 端口、WG 端口、安装目录等)在进入对应功能后按提示输入,菜单顶部实时显示安装/运行/入网状态。

所有文件(二进制/配置/数据)集中安装在**运行 sudo 的用户主目录**下的 `~/lightpn`(hub 数据在 `~/lightpn/hub-data`,agent 身份在 `~/lightpn/identity`),只有 systemd 单元放在 `/etc/systemd/system` —— 装了什么一目了然,卸载即净。「安装/升级」可重复执行:升级二进制、修改公网地址 / SOCKS 端口时重跑即可。以下 runbook 为传统系统路径(`/usr/local/bin` + `/var/lib/lightpn`)的手工流程,与脚本安装的目录布局不同,二者不要混用。

## 端口与防火墙

### hub 机

| 端口 | 协议 | 方向 | 用途 | 防火墙 |
|---|---|---|---|---|
| 7440 | TCP | 入站 | 控制通道(mTLS),所有 agent 回连注册/心跳 | **必须放行**,公网可达 |
| 7441 | TCP | 仅本机 | Web 面板 + REST/WS,只绑 `127.0.0.1` | **不要放行**,经 Cloudflare Tunnel 暴露 |

hub 不参与数据面,无需放行任何 UDP 端口。`cloudflared` 只向 Cloudflare 发起出站连接,同样不需要入站规则。

### agent 机

| 端口 | 协议 | 方向 | 用途 | 防火墙 |
|---|---|---|---|---|
| 51820(默认,可改) | UDP | 入站 | WireGuard 数据面,对端 agent 直连 | **必须放行**,公网可达且不经端口转换 NAT |
| 1080(示例,`--socks-port`) | TCP | 仅 overlay | 出口 SOCKS5,只绑 overlay IP(如 `100.100.0.3`),流量本就在 WG 隧道内 | 无需放行 |

WG 端口用脚本安装的「WG 端口」选项或 `--wg-port <N>` 自定义,放行对应的 `N/udp` 即可;hub 会向对端通告 `<本机公网IP>:<N>`,故该端口必须原样公网可达。link 状态 `degraded` 最常见的原因就是这里没放行。

出站方向:agent 需能主动连到 hub 的 `7440/tcp` 以及对端 agent 的 WG UDP 端口;默认放行出站的防火墙无需额外配置。

## 从零到三节点(runbook)

### 1. hub(1C1G VPS 即可)

以下命令在仓库根目录执行(写系统目录均需 root):

```sh
sudo install -m 755 bin/lightpn-hub /usr/local/bin/
sudo install -m 644 deploy/lightpn-hub.service /etc/systemd/system/

# 初始化管理员密码(交互输入,至少 8 位)
sudo /usr/local/bin/lightpn-hub admin set-password --data-dir /var/lib/lightpn/hub

# 告诉 agent 用哪个公网地址回连(强烈建议显式配置)
sudo mkdir -p /etc/lightpn
echo '{ "public_addr": "203.0.113.10:7440" }' | sudo tee /etc/lightpn/hub.json
# 然后编辑 /etc/systemd/system/lightpn-hub.service,
# 在 ExecStart 行末尾加上: --config /etc/lightpn/hub.json

sudo systemctl daemon-reload
sudo systemctl enable --now lightpn-hub
```

> `set-password` 这里写绝对路径,是因为部分发行版 sudo 的 `secure_path` 不包含 `/usr/local/bin`,直接 `sudo lightpn-hub` 会报 `command not found`。

防火墙:放行 `7440/tcp`(控制通道);**不要**放行 7441(面板只绑 127.0.0.1)。

### 2. 面板经 Cloudflare Tunnel 暴露

```sh
cloudflared tunnel create lightpn
cloudflared tunnel route dns lightpn panel.example.com
# config.yml: ingress 指向 http://127.0.0.1:7441
systemctl enable --now cloudflared
```

推荐在 Cloudflare Zero Trust 上给该域名加 Access 策略(email OTP),形成双层认证。

### 3. 边缘节点入网

面板生成 token 时会直接给出**完整的一步到位入网命令**:已含 `sudo`(secure_path 兼容),配了 `public_addr` 时自动填入真实 `ip:port`,末尾链上 `&& sudo systemctl enable --now lightpn-agent` 使节点入网后自动上线 —— 用脚本安装的 agent 复制粘贴即可。以下是等价的系统路径手工流程:

```sh
sudo install -m 755 bin/lightpn-agent /usr/local/bin/
sudo install -m 644 deploy/lightpn-agent.service /etc/systemd/system/

# 入网(写 /var/lib/lightpn/identity,需 root)
sudo /usr/local/bin/lightpn-agent enroll --hub 203.0.113.10:7440 --token lp_xxxxxxxx

sudo systemctl daemon-reload
sudo systemctl enable --now lightpn-agent
```

要求:Linux ≥ 5.6(内核内建 WireGuard)、iproute2、放行本机 WG UDP 端口(默认 51820)。需自定义时用脚本安装的「WG 端口」选项或给 agent 加 `--wg-port <N>`,并放行对应的 `N/udp`;hub 会向对端通告 `<本机公网IP>:<N>`,故该端口须公网可达、且不要落在做端口转换的 NAT 后。

### 4. 建立连接

面板「连接」页,在矩阵中点击两节点交叉处的 ＋ 即可;两侧 overlay IP(默认 `100.100.0.0/24` 段)随即互通。link 状态 `degraded` 通常意味着 WG UDP 端口未放行。

## 出口节点(经对端出网)

典型用法:边缘节点 A 作为翻墙入口(承载 Reality/VLESS 等协议),平时直连公网;一旦 hub 把 A↔B 撮合并指定 B 为出口,A 的出站流量就改为经 LightPN 隧道从 B 出网 —— 链路变成 `客户端 —(Reality)→ A —(LightPN)→ B → 公网`。

实现方式是 agent 内置一个**可切换上游的本地 SOCKS5**:翻墙软件的出站永远指向它,由 agent 依 hub 的撮合状态决定这个 SOCKS 直连还是链式转发到 B 的 overlay SOCKS。因为上游只认 B 的 **overlay 地址**(按 NodeID 稳定),底层 WG 换钥/重启的自愈对它透明,翻墙软件配置一次写死即可。

**每台要参与出口的机器都开启 agent 的 SOCKS**(出口节点必须开,入口节点开了才能把自己的翻墙出站接进来):

```sh
# ExecStart 追加,或命令行运行:
#   --socks-port 1080   在 overlay IP 上监听 1080,并向 hub 通告"我可作为出口"
lightpn-agent --data-dir /var/lib/lightpn/identity --socks-port 1080
```

- SOCKS 绑定在节点的 **overlay IP**(如 `100.100.0.3:1080`),不出现在公网接口。
- 入口机上的翻墙软件把出站指向本机 overlay 地址(如 `100.100.0.2:1080`)。
- overlay 内 SOCKS 明文流量本就在 WG 隧道里(已加密 + 双向 mTLS),不额外引入暴露面。

**切换出口**:面板「连接」页每条 link 的「出口」列选择方向(`A 经 B 出网` / `B 经 A 出网` / 直连);只有通告了 SOCKS 的节点才会作为可选出口出现。选定后 hub 向入口侧推 `peer_update`,agent 立即把 SOCKS 上游切到出口节点;改回「直连」即恢复。link 删除或出口节点掉线,入口自动回退直连。

**手动/测试**:不依赖 hub 时可用 `--exit-via 100.100.0.3:1080` 直接钉住上游(此时忽略 hub 的出口指令)。

## 在面板查看边缘节点的工具配置

节点详情页的「网络工具配置」区,点击「拉取配置」即经控制通道实时向该 agent 请求:

- **WireGuard 运行时状态**:接口名、监听端口、本机公钥、内核 peer 数 —— 不含私钥(WG 私钥只存在于 agent 内存与内核,设计不变量)。
- **翻墙软件配置文件**:agent 在内嵌的常见路径白名单中自动探测(xray / sing-box / v2ray / hysteria / trojan-go / mihomo / clash 的标准安装路径),读到什么展示什么。路径白名单编译在 agent 内,hub 无法指定任意路径,故 hub 被攻陷也不能借此读取边缘机器的任意文件。

安全须知:配置中的敏感字段(私钥/UUID/密码等)在面板中**默认打码、点击才显示**,但内容是明文经 Cloudflare Tunnel 送达浏览器的 —— Cloudflare 在其边缘可见面板明文。接受此暴露面的前提是你信任 Cloudflare(与本项目威胁模型一致);介意者请勿在面板拉取配置,改用 SSH 查看。

每次拉取都是现场读取,hub 不缓存、不落盘;节点离线时不可查(HTTP 409),agent 超过 10 秒未响应报超时(HTTP 504)。

> 说明:数据面出口依赖内核 WireGuard,仅 Linux 生效;非 Linux 平台 agent 用内存桩,SOCKS 切换逻辑仍可跑通用于开发。

## 运维要点

| 事项 | 说明 |
|---|---|
| 备份 | 只需备份 `/var/lib/lightpn/hub`(SQLite + CA 密钥)。**CA 丢失 = 全网重新入网** |
| hub 重启 | 不影响已建立的隧道;窗口期内仅撮合与监控不可用 |
| agent 重启 | 自动重新注册,对端在一个推送周期内拿到新 WG 公钥,隧道自愈 |
| 节点删除 | 面板删除即级联:清 link → 对端移除 peer → 踢下线 → 吊销证书 → IP 进 30 天冷却池 |
| 指标历史 | 内存 ring buffer,24h × 30s 粒度,不落盘;hub 重启后从头累积 |

## 卸载

### 移除单个边缘节点(推荐路径)

在面板(或 `DELETE /api/nodes/{id}`)删除该节点即可:agent 收到 `kick` 后会自动清空内核 WG peer、销毁 `/var/lib/lightpn/identity` 并以 0 退出(systemd 单元配置了 `RestartPreventExitStatus=0`,不会拉起)。之后在边缘机器上收尾:

```sh
sudo systemctl disable --now lightpn-agent
sudo rm /etc/systemd/system/lightpn-agent.service /usr/local/bin/lightpn-agent
sudo systemctl daemon-reload
```

### 边缘节点离线时的手动卸载

节点已无法连上 hub(或 hub 已不存在)时,直接在边缘机器上:

```sh
sudo systemctl disable --now lightpn-agent
sudo ip link del lightpn0 2>/dev/null || true     # 移除 WG 设备(若还在)
sudo rm -rf /var/lib/lightpn                       # 身份证书与私钥
sudo rm /etc/systemd/system/lightpn-agent.service /usr/local/bin/lightpn-agent
sudo systemctl daemon-reload
```

如果 hub 还在运行,记得同时在面板里删除该节点,让 hub 完成级联清理(移除对端 peer、吊销证书、回收 overlay IP)。

### 卸载 hub(拆除整套系统)

先明白两件事:hub 下线**不会**中断已建立的隧道(数据面独立);删除数据目录即销毁 CA,所有 agent 证书随之作废,之后无法再撮合。

```sh
sudo systemctl disable --now lightpn-hub
sudo systemctl disable --now cloudflared          # 若面板走 Cloudflare Tunnel
sudo rm -rf /var/lib/lightpn/hub                   # SQLite + CA 密钥(不可逆)
sudo rm -rf /etc/lightpn
sudo rm /etc/systemd/system/lightpn-hub.service /usr/local/bin/lightpn-hub
sudo systemctl daemon-reload
```

然后逐台按上面「离线手动卸载」清理边缘节点;若在 Cloudflare 上建过 Tunnel/Access 策略,一并删除。

## 开发

```sh
go test ./...        # 单元 + 端到端协议测试(含 §12 风险矩阵)
go vet ./...
```

非 Linux 平台上 agent 使用内存桩替代内核 WireGuard,协议全流程可在任意平台开发调试。

## 代码结构

```
cmd/lightpn-hub/      hub 入口 + admin set-password 子命令
cmd/lightpn-agent/    agent 入口 + enroll 子命令
internal/proto/       控制通道协议(4B 长度前缀 + JSON 信封)
internal/pki/         自签 CA、CSR 签发、身份材料
internal/hub/         存储(SQLite)、IPAM、控制通道、撮合、ring buffer、管理 API、内嵌面板
internal/agent/       身份持久化、主循环、wgctrl 设备管理、gopsutil 指标
deploy/               systemd 单元
```
