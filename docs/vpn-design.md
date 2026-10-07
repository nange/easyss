# easyss VPN 组网设计文档

> 状态：设计定稿；阶段 0-8 已实现，实施记录与对本文档的修正见 [第 12 节](#12-实施记录)。
> 依赖：`github.com/tailscale/tailcat` v0.7.0 + `tailscale.com`。
> 本文档中的技术结论均来自对 tailcat / tailscale 源码与当前仓库的实测，依据见 [附录 A](#附录-a实测依据)。

## 1. 背景与目标

easyss 目前只有代理能力：客户端把流量经隧道送到服务端，由服务端代为访问目标。本文档定义在此之上增加 **VPN 组网** 能力，使各 easyss 客户端节点与服务端节点互相可达。

**目标**

1. 任意两个节点之间可以互相访问**对端节点自身的服务端口**（如 `sshd` 的 22、Web 的 8080、数据库的 3306），从而支持节点间 SSH、HTTP、数据库互通。
2. DERP 中继服务由 easyss 服务端**内嵌**，完全不依赖 Tailscale 官方的 relay 与 control plane。
3. 访问方既可以用现有 SOCKS5 代理，也可以在 **TUN 模式下不指定任何代理** 直接使用（`ssh user@b`、`curl http://b:8080/`）。
4. 可强制「只经服务端中继」，不走节点间直连（应对国内跨省 UDP QoS 限速）。
5. `vpn.enabled=false`（默认）时对现有功能**零影响**。

**非目标（本期明确不做）**

- 访问对端节点的**内网**（对端只是服务出口，不是跳板机，见 [第 7 节](#7-安全边界)）。
- **ICMP**：VPN 只承载 TCP 与 UDP，`ping <host_name>` / traceroute 到对端**不通**（这是设计边界，不是 bug）。
- 节点的动态发现（对端地址由运维配置）。
- 托盘 UI、Android 的 VPN 配置面。
- DERP 的 metacert 快速路径与 WebSocket 传输。
- `relay_only=false` 下的 TUN 模式（架构上不可行，见 [8.1](#81-为什么-tun-模式必须-relay_onlytrue)）。
- **HTTP 代理入口**（`-x http://127.0.0.1:4080`）不对对端分流：VPN 注入面只接在 SOCKS5 路由上（见 [5.3](#53-访问侧把-vpn-注入现有-socks5-的路由)），而 TUN 模式的全部流量本来就走 SOCKS5，因此"透明访问对端"不受影响。用 HTTP 代理想访问对端时，请显式改用 SOCKS5（`socks5h://`）。

## 2. 关键约束（实测结论）

这一节是整个设计的地基。**这些约束直接决定了架构形态，任何实现都必须遵守。**

### 2.1 tailcat 的能力边界

| 事实 | 依据 | 影响 |
|---|---|---|
| **tailcat 客户端完全不接受入站连接** | `Client.initLocked` 中 `GetTCPHandlerForFlow` 直接 `return nil, true`（`tailcat.go:1957`）；包过滤器 `localNets` 只含本机地址，仅放行非 SYN 续流 | 任何节点都无法「被别人拨进来」，除非它自己跑 tailcat **Server** |
| tailcat **Server 没有 netstack 拨号 API** | `Server` 只导出 `Start/Close/Addr/TailcatAddr/Listen/AddAllowedClient/DrainTCP/Status` | 服务端**无法**把 A 的连接在应用层转发给 B（`OnTCPForward` 走宿主网络栈，只服务 exit-node/subnet-router 场景） |
| tailcat 地址**自包含**（前提是完整格式） | `ConnInfo.Addr()` 把服务端公钥、disco 公钥、PSK、DERP region 详情编码为 `tc...`；`ParseAddr` 解析后 `Expand` 是 no-op。**短格式只带 region ID，客户端会去拉 `tailcat.dev/derpmap.json`** | 零控制面：拿到**完整格式**地址即拿到全部连接信息。因此 peer 地址必须是完整展开格式，见 [4.7](#47-peer-地址必须是完整展开格式) |
| 节点虚拟 IP 由**公钥确定性派生** | `tcAddrForKey`（`tailcat.go:1755`）：`fd7a:115c:a1e0::/48` + 公钥前 10 字节 | **零 IP 分配**：没有租约、没有注册表、重启不变 |
| UDP 单包上限 **1232 字节** | `MaxUDPPayload`（`tailcat.go:554`）：隧道 IPv6 MTU 1280 减 40+8 头 | UDP 可用但不适合大包 |
| 打洞失败时经 DERP 转发 | magicsock 的 DERP 兜底路径 | 「打不通时经服务端转发」是原生行为 |

### 2.2 拓扑推导：为什么是「A 以 B 为 server」

由 2.1 前两条可推出唯一可行形态：

- B **必须**跑 tailcat Server，否则它的端口不可达（客户端不接受入站）。
- A **必须**以 B 为 tailcat server（A 跑 tailcat Client），否则 A 与 B 之间不存在 WireGuard 会话，DERP 也无从转发。

于是：

```
A ──tailcat.Client(B)──▶ B ──tailcat.Server──▶ B 的 peer-facing SOCKS5
```

**这同时回答了「服务端如何转发」**：DERP 转发的是**两个已建立 tailcat 会话的节点之间的 WireGuard 报文**。A 与 B 有会话，打洞失败时数据经 DERP（就在 easyss 服务端）转发——这正是「A 到 B 打不通时经服务端转发」，无需服务端参与应用层转发，也无需 fork tailcat。

> 被否决的拓扑：A 与 B 都是同一个 hub 服务端的 Client，指望 hub 在应用层转发。这不可行（2.1 第二条）。

### 2.3 为什么不需要控制面与 IP 分配

- 地址里已含公钥、PSK 与 DERP region ⇒ 配置里粘一串地址即可，不需要注册/发现接口。
- 虚拟 IP 由公钥派生 ⇒ 不需要 DHCP 式的分配与冲突处理。
- 因此配置项可以压缩到：一个开关、一个可选的中继开关、一个端口、一份对端列表。

### 2.4 强制「只走中继」

需求：应对国内跨省 UDP QoS，要能禁用节点间直连。

实现：启动时 `envknob.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "true")`（`envknob.Setenv` 是导出 API，见 `envknob.go:94`）。实测该开关使 magicsock 绑定 `newBlockForeverConn()`（`magicsock.go:3706`），**完全不创建 UDP socket**，所有对端通信强制走 DERP（`debugknobs.go:37`）。

**风险**：该开关名带 `TS_DEBUG_`，属调试开关，未来 tailscale 版本可能改动。缓解：`go.mod` 锁定 tailscale 版本、启动时打印告警、提供 `pathcheck` 运行时自检（用 `Client.Ping` 报告实际路径是 DERP 还是直连）。它是**进程级**的，不能按对端区分。

### 2.5 easyss TUN 模式的现状

| 事实 | 依据 | 影响 |
|---|---|---|
| TUN 的流量**只有一个 SOCKS5 出口** | `client/tun/tun.go:312` `Proxy: m.cfg.Socks5Addr` | VPN 必须成为**该 SOCKS5 的一个路由目标**，而不是另开端口（见 3.2） |
| tun2socks **不嗅探域名** | `engine.Key` 仅有 `Proxy/MTU/UDPTimeout/TCP*Buffer*` 等字段 | 进入 SOCKS5 的是**目标 IP**，因此 `ssh user@b` 必须先由 DNS 把 `b` 解析成一个可路由 IP |
| TUN 把所有 IPv4（除 `0.0.0.0/8`）路由进设备 | `scripts/create_tun_dev.sh:103-110` 的 `1.0.0.0/8 … 128.0.0.0/1` 阶梯 | 任何新增的 overlay 段都会被自动捕获；但也会捕获 tailcat 自己的出网流量（见 8） |
| easyss 自身传输靠**绑定物理接口**绕开 TUN | `Client.initDirectDialer`（`client/client.go:167`） | tailcat **没有**对应 API，因此 TUN 下必须换一种绕开方式（见 8.1、8.2） |
| TUN 模式把系统 DNS 指向一个**公网**解析器，其查询经 TUN 到达 **SOCKS5 入口的 DNS 拦截器** | `client/tun/tun.go` `saveAndSetDNSStep` + `cmd/easyss/main.go` 的 `tunDNS`→`PreferredSystemDNS`；拦截在 `client/proxy/dns.go` | 对端名字的静态解析必须挂在 `client/proxy` 的拦截器上（`client/dns` 的转发服务器只服务 `enable_forward_dns` 的 LAN 部署）；见 [5.4](#54-对端名字的静态解析) 与 [12.8](#128-阶段-6-的实现记录) 第 36 条 |

## 3. 架构

### 3.1 角色

| 角色 | 由谁承担 | 说明 |
|---|---|---|
| **DERP 中继 S** | 由 `derp_addr` 显式指定；客户端未指定时取 `servers[]` 中被 `derp: true` 标记的那条（未标记则 `servers[0]`）；服务端未指定时取 `domain` + `listen` 的端口（见 [4.6](#46-derp_addr-与默认规则)） | 内嵌 DERP，提供会合与中继；不参与 tailcat 会话建立 |
| **对端面（被访问方）** | 任何 `vpn.enabled=true` 的节点 | 跑 tailcat Server，在隧道内提供 peer-facing SOCKS5 |
| **访问侧** | 需要访问别人的节点 | 为 `peers` 中列出的每个对端跑一个 tailcat Client |

> 节点同时具备后两个角色，**没有单独的 `expose` 开关**（早期设计中的 `expose: false` 已删除：它只为省一套 netstack，却带来理解成本）。

### 3.2 数据流

```
A 的应用
   │ ① TUN 模式：系统 DNS 把 b 解析为 overlay IP 198.19.0.x
   │    → 命中 TUN 路由 → tun2socks → SOCKS5 CONNECT 198.19.0.x:8080
   │ ② 非 TUN：SOCKS5 CONNECT b:8080
   ▼
现有 SOCKS5 服务（127.0.0.1:<local.socks_port>，复用）
   │ routePolicy 的 VPN 前置判定：host_name 或 overlay IP 命中 peers
   ▼ routeVPN：把 dst 归一化为字面 127.0.0.1:<port>
   │           （b 与 overlay IP 都只是 A 侧本地概念，不会进隧道）
   ▼
tailcat.Client(B) ──WireGuard / DERP(S)──▶ B 的 tailcat.Server
                                            │ Listen("tcp"|"udp", ":<B 的 peer_port>")
                                            ▼ 复用 Socks5Server（只接受字面 loopback 目标）
                                            ▶ B 的 127.0.0.1:<port>
```

**关键设计**：访问侧**不新增监听端口**，而是把 VPN 作为现有代理 SOCKS5 的一个**路由目标**。这样：

- 非 TUN 时应用配置现有代理端口即可同时上网和访问对端；
- TUN 时 tun2socks 的单一出口天然把流量送到同一条路径上，透明访问成立。

对端面确实需要「一个端口号」，但它是**隧道内**的端口（gVisor netstack 里），**不在宿主上监听**，因此与宿主端口不会冲突。

内层 CONNECT 的目标契约见 [5.1](#51-对端面复用-proxysocks5server)，这是访问侧与对端面之间**唯一的跨节点协议契约**。

### 3.3 DERP 私有化：只经 easyss 隧道，且要求单一 S

**标准做法（已实施，替代本节原先的"DERP 挂在公网 HTTPS 上"）**：内嵌 DERP 只接待来自**本机回环**的请求，节点侧则把 tailcat 到 DERP 的连接放进 easyss 隧道。链路是：

1. 节点侧：`runner.newDERPDialer` 构造一个拨号器交给 tailcat（`Server.DERPDialer`/`Client.DERPDialer`），把每条 DERP TCP 连接经 `StreamHandler.OpenTCPStream` 送进 easyss 隧道（`net.Pipe` 适配：一端交给 handler 搬运，另一端返回给 tailcat）。拨号上下文必须 `context.WithoutCancel`——DERP 客户端在拨号返回后立刻取消它，而这条流的寿命是整个 DERP 连接；
2. 服务端在握手阶段认出"目标就是我自己的 `derp_addr`"，改拨 `127.0.0.1:<listen>`（`server/handler` 的 `localDERP`/`dialTarget`）；
3. `vpn.NewDERPMount` 只把来自回环的 DERP 流量交给中继，公网上的 `/derp`（含 `POST /derp/probe` 这类探测）一律得到伪装页面。

**为什么必须是拨号器选项，而不是环境变量**：tailcat 在自己的 `createEngine` 里调用 `netns.SetEnabled(false)`，于是 `netns.NewDialer` 返回的是**未包装**的普通拨号器，`ALL_PROXY` 那条路在 tailcat 里完全不生效（本项目最初按它实现过一版，测试只覆盖了 netns 层而没有走 tailcat 的真实路径，因此是个假阳性）。拨号器选项还顺带解决了平台差异（netns 的 SOCKS 包装在 android/ios/js 构建里被排除）与"进程级开关只读一次"这两件事。

**代价：只支持单一 S。** 所有节点必须通告同一个 DERP `host:port`——因为 DERP 连接只到得了"本节点自己那台 easyss 服务端"的回环，服务端无法代表节点去连另一台机器。`vpnnode.assertPeersShareDERP` 在启动时校验 `peers[].address` 内嵌的 DERP 主机与本节点一致，不一致直接报错（否则表现为第一次访问对端时隧道拨号超时）。

**依赖面**：这两个选项目前由本项目自己的 fork 提供，`go.mod` 用 `replace` 指向同级目录（`../tailscale`、`../tailcat`，分支 `easyss/derp-dialer`）：

- tailscale：`derphttp.SetDialer`（并让 region 客户端也走它，原先只有 URL 模式生效）、`magicsock.Options.DERPDialer`、`wgengine.Config.DERPDialer`；
- tailcat：`Server`/`Client` 的 `DERPDialer` 与 `DERPOnly`（后者把 relay_only 从"调用方去写 tailscale 的调试开关"变成库的公开选项）。

上游接受前，本机验证用相对路径 replace；CI/发布需要换成 GitHub 上的 fork 版本。

## 4. 配置

### 4.1 服务端（DERP 主机 S）

```jsonc
{
  "server": {
    "listen": ":443",
    "domain": "example.com",
    "password": "your-password",
    "vpn": {
      "enabled": true,
      // 可省略：默认取 domain + listen 的端口（这里即 example.com:443）
      "derp_addr": "example.com:443"
    }
  }
}
```

> 注意服务端配置**没有 `port` 字段**，监听地址由 `listen` 表达（示例里写 `":443"`，但**没有**运行期默认值——`listen` 留空时 Go 的 `http.Server` 会监听 80），因此 DERP 端口默认从 `listen` 解析。
>
> DERP 的**挂载路径不可配**，固定为 `/derp`：客户端侧 `derphttp.Client.urlString` 把路径硬编码为 `/derp`（`tailscale.com/derp/derphttp/derphttp_client.go:293`），`derpserver.Handler` 也文档化要求「mounted at /derp」并在内部分流绝对路径 `/derp/probe`、`/derp/latency-check`（`derp/derpserver/handler.go:28`）。把它做成配置项只会提供一个一改就让所有节点连不上的开关，因此常量 `config.DefaultVPNDERPPath` 是唯一来源。

### 4.2 节点

```jsonc
{
  "servers": [
    { "address": "example.com",        "port": 443, "password": "...", "derp": true },
    { "address": "backup.example.com", "port": 443, "password": "..." }
  ],
  "vpn": {
    "enabled": true,
    "relay_only": true,
    "peer_port": 6080,
    "overlay_cidr": "198.19.0.0/24",
    // 可省略：默认取被 derp:true 标记的 server（未标记则 servers[0]）的 address:port
    "derp_addr": "example.com:443",
    "peers": [
      { "host_name": "b", "address": "tcXXXXXXXX..." }
    ]
  }
}
```

### 4.3 字段说明

| 字段 | 默认 | 说明 |
|---|---|---|
| `servers[].derp` | `false` | 标记「用这条 server 的 `address`/`port` 作为内嵌 DERP 的主机与端口」。**没有任何条目标记时回退 `servers[0]`** |
| `vpn.enabled` | `false` | 总开关。关闭时不监听、不启 goroutine、全链路零影响 |
| `vpn.relay_only` | `true` | 强制全部经 DERP、禁用节点间直连。见 2.4。**TUN 模式下必须为 true**（见 8.1） |
| `vpn.peer_port` | `socks_port + 2000`（即 4080→6080） | 本节点**对端面**在隧道内的端口，也是别人要拨的端口。越界回退常量 `DefaultVPNPeerPort = 6080`。派生方式沿用 `http_port = socks_port + 1000` 的既有惯例 |
| `vpn.overlay_cidr` | `198.19.0.0/24` | **访问侧本地概念**：给对端分配的 overlay 虚拟 IPv4 段，仅用于 TUN 模式的 DNS 应答与本地路由匹配。**不需要与其他节点一致**（对端永远不会看到它，见 5.1）。选 `198.19.0.0/24` 而非 `100.64.0.0/10` 是为避开 CGNAT 在物理接口上的 on-link 路由（见 8.3） |
| `vpn.derp_addr` | 标记的 `servers[]` 条目（否则 `servers[0]`）的 `address:port` | 本节点在**自己地址里通告**的 DERP 主机与端口（`host:port`）。仅当 DERP 不在代理服务端时（或跨 S）才需要显式写 |
| `vpn.peers[].host_name` | 必填 | 应用里书写的名字（`http://b:8080/`、`ssh user@b`） |
| `vpn.peers[].address` | 必填 | 对端的 tailcat 地址，**必须是完整展开格式**（见 4.7），从对端启动日志复制（对端同时写入 `<exe>/vpn/peer.txt`） |
| `vpn.peers[].port` | `DefaultVPNPeerPort` | 对端的 `peer_port`。仅当对端自定义了该值时才需要写 |
| `vpn.allow_clients` | 空（不限制） | 允许接入的对端 node key 列表（`nodekey:...` 文本格式），直通 `tailcat.Server.AllowedClients`。配套要求见 [第 7 节第 3 条](#7-安全边界) |
| `server.vpn.derp_addr` | `domain` + `listen` 的端口 | 服务端对外通告的 DERP 主机与端口（`host:port`）。服务端**没有** `servers[]`，因此这是它表达「DERP 挂在哪个主机/端口」的地方；当 DERP 经端口转发或反代暴露在与代理监听不同的 host:port 时**必须**显式写 |

> **没有 `server.vpn.derp_path`**：挂载路径固定为 `/derp`，理由见 4.1 的说明。
> **没有 `vpn.peer_port` 之外的「隧道内端口」**：`peer_port` 只在本节点被访问时使用，对端通过 `peers[].port` 指定。

### 4.4 用法对照

```bash
# 非 TUN：用现有代理 SOCKS5 端口
curl --socks5-hostname 127.0.0.1:4080 http://b:8080/
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:4080 b 22" user@b

# TUN 模式：不需要任何代理参数
curl http://b:8080/
ssh user@b
```

**首次配置的取值来源**（两个 key 的收件人不同，这是最容易搞反的一步）：

```bash
# 在节点 X 上执行，拿到两样东西：
#   1) client nodekey → 填到**对端**的 vpn.allow_clients（对端面据此识别访问侧）
#   2) node address   → 填到**对端**的 vpn.peers[].address（内嵌公钥 / DERP / preshared key）
./easyss -show-vpn-identity
```

启动日志里同样会打印这两项（`[VPN] node identity ready`），地址另有一份落在
`<exe>/vpn/peer.txt`。`vpn.enabled=false` 时两处都不产生任何输出。

### 4.5 归一化归属

客户端与服务端都不把 VPN 的派生值写回配置结构体，而是由**一个访问器/解析器**在读取时给出有效值。理由有两条，都与既有惯例（`timeout`/`tun_mtu` 的写回）不同：

1. **命令行覆盖要能带动派生。** `applyDefaults` 在 `ApplySimpleOverrides`（`--local-port` 等）之前就跑完了；把 `peer_port` 写回结构体会把它冻结在「按旧 `socks_port` 派生」的结果上，于是 `--local-port 6000` 之后 `peer_port` 还是 6080。访问器没有这个时序问题。
2. **严格校验需要能返回错误。** `applyDefaults` 没有错误返回值，而 peer 地址必须是完整展开格式（4.7）这类契约必须在启动阶段**报错**，不能静默回退。

因此：

- 客户端：`client/config/vpn.go` 提供 `VPNPeerPort()`（`+2000` 派生与越界回退）、`VPNOverlayPrefix()`（校验，非法回退默认段并告警）、`VPNDERPAddr()`（默认取 `DERPServer()` 的 `address:port`）、`DERPServer()`（`derp` 标记优先，否则 `servers[0]`）、`VPNRelayOnly()`。**JSON 视图保持原样**，`VPN.PeerPort == 0` 始终表示「未配置」。
- 服务端：`server/config/vpn.go` 提供 `ResolveDERPAddr()`（显式值校验，否则由 `domain` + `listen` 的端口推导；推导失败**返回错误**）与 `ResolveDERPPath()`；`LoadConfig` 在 `vpn.enabled` 时调用 `validateVPN()`，使错误在启动阶段暴露。
- 严格校验与运行期视图：`vpn.NewConfig(Options)` 是 VPN 全部校验的唯一入口，客户端与服务端的 JSON 视图都只负责形状。
- 新增常量集中在 `config/vpn.go`（与 `config/tun.go`、`config/timeouts.go` 的分域惯例一致）：`DefaultVPNPeerPort`、`DefaultVPNOverlayCIDR`、`DefaultVPNDERPPath`、`DefaultVPNRegionID`、`NormalizeVPNPeerPort`、`ParseVPNOverlayCIDR`、`SplitDERPAddr`、`PortFromListen`。

### 4.6 `derp_addr` 与默认规则

两边都需要「一个可对外通告的 DERP 主机与端口」，但来源不同，这是服务端与客户端的根本差异：

| 侧 | 有 `servers[]` 吗 | 默认来源 | 何时必须显式写 |
|---|---|---|---|
| **客户端节点** | 有 | `derp: true` 标记的条目 → 否则 `servers[0]` 的 `address:port` | 一般不需要：DERP 私有化要求单一 S（3.3），显式写只能写成同一台 |
| **easyss 服务端** | **没有** | `domain` + `listen` 解析出的端口 | DERP 经端口转发/反代暴露（对外 host:port ≠ `domain:listen`） |

`socks_port + 2000` 这类**派生**只适用于有 `servers[]` 的客户端；服务端一律用 `domain` + `listen` 推导，或在 `server.vpn.derp_addr` 里显式给出。

从 `listen` 解析不出端口（例如只写了主机名）时，启动必须**失败并提示改用 `server.vpn.derp_addr` 显式指定**，而不是退回一个猜测值。两处细节：

- `listen: ":https"` 这类**服务名对 `net.Listen` 合法**（Go 会查表解析），因此推导也必须接受它，但结果要归一化成**数字**端口——对端只会把它读成 `DERPPort int`（`net.LookupPort`）。
- 服务端配置的 `listen` **没有运行期默认值**（`buildHTTPServer` 直接把它交给 `http.Server.Addr`），所以 `listen` 留空时推导必然失败——这正是应当报错的场景。

### 4.7 peer 地址必须是完整展开格式

tailcat 地址有两种形态：

- **完整格式**：内嵌 DERP 节点详情（HostName/IPv4/IPv6/Port）。客户端解析后不需要任何网络查询。
- **短格式**：只带 region ID。客户端会去拉 `https://tailcat.dev/derpmap.json`——这**违反本设计「零 Tailscale 官方依赖」的目标**。

因此定为硬契约：

1. 对端面的 `tailcat.Server` **必须设置 `Server.Region`**（而不是仅 `RegionID`），使 `TailcatAddr()` 天然产出完整格式。
2. **启动自检**：打印与写 `<exe>/vpn/peer.txt` 之前，解析该地址并断言 `Region` 非空且节点详情完整；不满足则**拒绝写入并大声报错**，绝不静默。
3. `peer.txt` 与启动日志**只允许**出现完整格式；`peers[].address` 也只接受完整格式（解析后 `Region` 为空的地址在配置校验阶段直接报错）。
4. 验收测试断言：端到端流程中**零** `tailcat.dev` / `derp*.tailscale.com` 请求。

## 5. 复用点与最小改动

### 5.1 对端面复用 `proxy.Socks5Server`

- 把路由器构造为 `ProxyRuleDirect` 后，`router.go:326-327` 的 `if rule == ProxyRuleDirect || r.isLANHost(host) → HostRuleDirect` 使**所有目标判为直连**，于是 `connectHandler` → `routeTCPReplied` → `routeDirect` → `directTCPConnect`（`socks5.go:403`）→ 注入的拨号器。`directTCPConnect` 本身不做 LAN 拒绝。
- `IPV6Rule` 用 `IPV6RuleEnable`（否则 `ShouldIPV6Disable()` 会拦掉 IPv6 目标）；`Handler: nil`、`DNSCache: nil`（全直连模式不会走隧道分支）。

**内层 CONNECT 目标契约（唯一的跨节点协议契约，实现阶段 3/4 必须严格按此对齐）**

| 侧 | 契约 |
|---|---|
| **访问侧（A）** | 命中 peer 后，把 dst **归一化为字面 `127.0.0.1:<port>`**，再写入隧道内的 SOCKS5 CONNECT（UDP 走 5.3 的一次性目标头，同样是字面 `127.0.0.1:<port>`）。`host_name` 与 overlay IP **绝不出现**在隧道里 |
| **对端面（B）** | 拨号器**只接受字面 loopback 目标**（`127.0.0.0/8` 或 `::1`），校验通过后按该字面地址拨号；**域名（含 `localhost`）与其他一切目标一律拒绝** |

由此得到两个重要结论：

- B **不需要**关于访问侧的任何跨节点知识：既不知道 A 起的昵称，也不知道 A 的 overlay 网段 ⇒ **不存在「两端 `overlay_cidr` 必须一致」的同步要求**，配置面更小。
- 安全边界最简单且可证明：B 只可能拨自己的 loopback，**不可能成为内网跳板**。

**另外**：对端面需要**关闭 53 端口拦截**（`Socks5Options` 新增一个小开关），否则对端本机监听在 53 的服务（如 systemd-resolved）无法通过 VPN 访问——现有 `connectHandler` 会把 53 当作 DNS over TCP 截走（`socks5.go:329-331`）。

### 5.2 需要新增的方法

```go
// client/proxy/socks5_lifecycle.go
// Serve 在调用方提供的 listener 上服务（Start 改为调用它）。
func (s *Socks5Server) Serve(ln net.Listener) error
```

约 15 行，把现有 `Start()` 拆开，**不改变任何既有行为**。

### 5.3 访问侧：把 VPN 注入现有 SOCKS5 的路由

为把对核心代理路径的改动收敛且可关闭，采用**可选注入**：`Socks5Options` 新增 `VPN VPNRoute` 接口字段，`nil` 表示功能关闭，行为与今天完全一致。

| 文件 | 改动 |
|---|---|
| `client/proxy/route.go` | 新增 `routeVPN` 动作与 `VPNRoute` 接口（**接口定义在消费方**：`vpn/node` 已经依赖本包，反向依赖会成环）；`routePolicy.decide()` **在调用 router 之前**先查 `vpn.Lookup(host)`（`host` 可能是 `host_name` 或 overlay IP），命中则返回 `routeVPN` |
| `client/proxy/socks5.go` | `Socks5Options.VPN` 注入；`routeTCPReplied` 新增 `case routeVPN:` → `vpn.DialTCP(ctx, target)`（内部完成「按 peer 拨隧道 + CONNECT 字面 `127.0.0.1:<port>`」）→ `relayTCP(...)`；`connectHandler` 在 53 拦截之前判定对端（否则对端面的 53 在 TCP 侧不可达） |
| `client/proxy/udp.go` | `handleUDP` 在**所有公网路径门禁之前**判定对端，命中即进 `vpnUDPRelay`：复用同一套会话池与读循环（key 加 `vpn_` 前缀并用对端规范名），只替换拨号器 |
| `client/proxy/udp_pool.go` | `acquireDirectWith(key, dst, dial)`：让会话池接受一个按会话给出的拨号器，VPN 与直连因此共用同一套会话表、上限驱逐与空闲回收 |

### 5.4 对端名字的静态解析

客户端有**两个** DNS 前端，对端名字必须在两个上都成立（实施修正如 [12.8](#128-阶段-6-的实现记录) 第 36 条）：

- **代理的 DNS 拦截器**（`client/proxy/dns.go`）：TUN 模式下系统解析器写的是一个**公网 DNS**（`cmd/easyss` 的 `tunDNS` → `PreferredSystemDNS`），查询经 TUN → tun2socks → 本机 SOCKS5 的 53 端口到达这里。**这是 TUN 模式唯一会走到的路径**（`ssh user@b` 靠它）。
- **转发 DNS 服务器**（`client/dns/forward.go`，仅 `enable_forward_dns` 时运行）：把 easyss 部署在路由器/软路由上、LAN 设备的 DNS 指向本机时走它。

两者共用同一份应答语义（`dns.StaticReply`），行为写死为：

- **A 查询**：返回该对端的 overlay IPv4。
- **AAAA 查询**：返回 **NOERROR 且无记录**（不是 NXDOMAIN、不返回异常），使客户端立即回退到 A 记录——overlay 段只有 IPv4。
- 非 peer 名：原样转发，行为不变；其他 qtype（MX/TXT/HTTPS 等）同样原样转发。
- 钩子是可选注入：代理侧由 `Socks5Options.VPN` 的注入面**可选地**实现（`client/proxy.VPNStaticNames`），转发服务器侧由 `NewForwardServer` 的 `static` 参数给出；两者为 `nil` 时行为与今天完全一致。

### 5.5 TUN 阶段的脚本改动

**已不需要**：DERP 连接走回环入口（3.3），不再有任何"必须绕出 TUN 的 DERP 主机"，因此三个创建脚本保持改动前的 9 个位置参数。

## 6. 新增 `vpn` 包

**包结构（实施中修正，理由见 12.4）：`vpn` 与 `vpn/node` 两个包，分界线是「是否引用 `tailcat`」。**

- **`vpn`（不引用 `tailcat`）**：DERP 中继、region 构造与校验、状态目录与密钥持久化。服务端二进制只依赖它。
- **`vpn/node`（引用 `tailcat`）**：一个 easyss 节点自身的 VPN 栈——身份、配置校验与运行期视图、overlay、对端面、薄 UDP 中继，以及（阶段 4 起的）访问侧。

这条分界线不是审美问题，而是**实测 +14 MiB** 的二进制代价：服务端只需要 `derpserver` 跑中继，而任何对 `tailcat` 的引用都会把整个 WireGuard 引擎与 gVisor netstack 拖进去。`vpn/deps_test.go` 用 `go list -deps` 把这条不变量钉住。

| 文件 | 关键符号 | 职责 |
|---|---|---|
| `vpn/state.go` | `StateDir`、`NodeIdentityPath`、`ClientKeyPath`、`DERPKeyPath`、`PeerFacePath`、`LoadOrCreateKey`、`LoadOrCreate` | 状态目录与密钥持久化（只依赖 `types/key`）：文件 0600、目录 0700、临时文件加 rename 的原子写；损坏时报错并提示删除重建，**不静默覆盖**。三份长期密钥对端面 node key（地址稳定）、**访问侧 client key（`allow_clients` 硬化的前提，必须跨重启稳定）**、DERP ed25519 密钥 |
| `vpn/derp.go` | `DERPServer`、`NewDERPServer`、`Handler()`、`Close()`、`PublicKey()` | `derpserver.New` + `derpserver.Handler`；slog → `logger.Logf`；**不启用** client 校验（默认即关，无需 tailscaled） |
| `vpn/mount.go` | `Fallback`、`NewDERPMount` | 在 `/` 的兜底处理器内部按路径分流：只有真实 DERP 协议请求（`Upgrade: derp\|websocket`）与 `/derp/probe`、`/derp/latency-check` 进中继，其余一律走伪装页面（否则 `derpserver.Handler` 会回一个带 "DERP requires connection upgrade" 的 426，一眼可辨） |
| `vpn/region.go` | `RegionID`、`RegionCode`/`RegionName`/`DERPNodeName`、`BuildRegion(derpAddr)`、`ValidateRegion(region)` | `DERPNode{HostName: <derp_addr 的 host>, DERPPort: <derp_addr 的 port>, Name: "easyss-derp"}`，region 编号取 `config.DefaultVPNRegionID`（**必须非零**，`Server.Start` 拒绝 0；`ValidateRegion` 在构造期拦住它，见 12.5 第 12 条） |
| `node/identity.go` | `NodeIdentity`、`LoadOrCreateNodeIdentity`、`NodeKeyString` | tailcat 服务端身份（直接复用 `tailcat.PrivateKey`：**disco 公钥无法从 node 私钥推导**，没有导出 API）。`NodeKeyString()` 供 CLI 与启动日志打印本机 `nodekey:...`（对应 tailcat `genkey --client` 的语义） |
| `node/addr.go` | `AssertFullAddr(addr)` | 实现 4.7 的启动自检：region 非空、至少一个带 HostName 的节点、带 disco 公钥 |
| `node/config.go` | `Config`、`Options`、`NewConfig(Options)`、`PeerRef{HostName,Address,Port}` | 运行时视图；`peer_port`/`overlay_cidr`/`derp_addr` 的范围与形态校验、`peers[].host_name` 的唯一性与合法性、`allow_clients` 的解析，**全部集中在 `NewConfig`**（`applyDefaults` 没有错误返回值，承载不了必须报错的契约）。`Options` 是原始输入、`Config` 是已验证的视图，两者分开使「未配置」与「显式配置为默认值」在类型上仍可区分 |
| `node/overlay.go` | `Overlay`、`Assign(prefix, peers)`、`Addr`、`Lookup`、`Peers` | 由对端公钥哈希在 `overlay_cidr` 内确定性分配 IPv4（先按公钥排序再线性探测避碰），与配置顺序无关；`Lookup` 同时接受 host_name（不区分大小写）与 overlay 字面 IP |
| `node/peerface.go` | `PeerFace`、`NewPeerFace`、`Start/Stop`、`TailcatAddr`、`NodeKey`、`PublishAddr`、`LoopbackDialContext` | 对端面：tailcat Server（**必须设 `Region`**）+ `Listen("tcp"\|"udp", ":<peer_port>")`；TCP 桥到 loopback-only 的 `Socks5Server`（关闭 53 拦截），UDP 桥到 `UDPRelay`；地址在构造期自检、`PublishAddr` 写 `peer.txt` |
| `node/udprelay.go` | `UDPRelay`、`Serve(ln net.Listener)`、`EncodeUDPTarget`、`DecodeUDPTarget` | 对端面薄 UDP 中继：一次性目标头（**字面 `127.0.0.1:<port>`**，非 loopback 一律拒绝）+ 原始数据报双向；两方向共享活动时间戳，任一方向结束即拆流 |
| `node/route.go`（阶段 4） | `Route`、`RouteOptions`、`NewRoute`、`Lookup`、`DialTCP`、`DialUDP`、`socks5Connect`、`targetHeaderConn` | 访问侧：`host_name`/overlay IP → 对端；**统一把 dst 归一化为字面 `127.0.0.1:<port>`**（`const innerTargetHost`）；TCP 走 SOCKS5-over-tunnel，UDP 走隧道 UDP 流 + 一次性目标头。它实现 `client/proxy.VPNRoute`——**接口定义在消费方**（`client/proxy/route.go`），因为 `vpn/node` 已经依赖该包，反向依赖会成环 |
| `node/clients.go`（阶段 4） | `ClientSet`、`ClientSetOptions`、`NewClientSet`、`ClientKey`、`Close` | 按对端地址维护 tailcat Client（一个对端一个引擎），整组共用一份**持久化** client key（`vpn.ClientKeyPath()`，`allow_clients` 的前提）。客户端懒创建：构造不发起网络活动、不留 goroutine，未使用的 `Close` 是空操作 |
| `node/dnsnames.go`（阶段 6） | `ResolveStatic(name)` | 供 `dns.ForwardServer` 的静态名钩子使用，实现 A/AAAA 两条契约（5.4） |
| `node/bypass.go`（阶段 7） | `BypassIPs(cfg)` | 计算需绕行 TUN 的 DERP 主机 IP **并集**：本地标记的 S **+ 所有 `peers[].address` 内嵌 DERP 的 `HostName`**（跨 S 时后者必需）。本地 S 复用 `Core.publishServerIPs` 的结果，peer 侧由本包解析并缓存 |
| `node/pathcheck.go`（阶段 5） | `Path`、`PathStatus(ctx, *tailcat.Client)` | 排障：报告实际承载路径（`direct <addr>` 或 `via DERP(<code>)`），用于确认 `relay_only` 生效。用 `DiscoPing` 而不是 `Client.Ping`——后者**总是**测 DERP 路径，无论 `relay_only` 是什么都回报中继，证明不了任何事 |
| `node/relayonly.go`（阶段 5） | `RelayOnlyEnvKnob`、`ApplyRelayOnly(on bool)` | 把 `relay_only` 接到 tailscale 的进程级调试开关上（`envknob.Setenv`）。三条约束写在函数注释里：进程级、必须在任何 tailcat Server/Client 启动之前、必须显式写 true 与 false（见 12.7 第 22 条） |

## 7. 安全边界

1. **只允许对端自身服务**：见 5.1 的内层 CONNECT 目标契约——对端面只接受字面 loopback 目标。
   - 可达：监听在 loopback 或 `0.0.0.0` 的服务。
   - 不可达：只绑在某个内网 IP 上的服务，以及其他一切非 loopback 目标（刻意的）。
2. **不动既有防线**：不修改 `util.IsLANIP`，也不把 VPN 数据面接进 `server/handler` 的 `dialer`/`dialOutbound`（Tailscale 带内段与 `100.64.0.0/10` 重叠，混用会误伤）。代理路径的 SSRF 防护原样保留。
3. **接入凭据与 `allow_clients` 的配套要求**：
   - tailcat 地址本身含 PSK，是秘密；地址泄露等于把对端面的接入能力给出去。
   - 可选硬化：`vpn.allow_clients: ["nodekey:..."]` 直通 `tailcat.Server.AllowedClients`。启用它的前提是：
     - **访问侧的 client node key 必须持久化**（`LoadOrCreateClientKey`），否则每次重启换 key、白名单立刻失效；
     - **访问侧必须能打印本机 nodekey**（启动日志一行 + CLI 输出），否则运维无从填写白名单；
     - `allow_clients` 里的字符串按 `nodekey:...` 文本格式解析。
4. **`local.bind_all=true` 的含义**：局域网内也能通过本机的代理 SOCKS5 端口访问其对端（受既有 SOCKS5 认证约束）。需要在文档中明确提示。

## 8. TUN 透明访问的前提

### 8.1 为什么 TUN 模式必须 `relay_only=true`

TUN 把除 `0.0.0.0/8` 外的所有 IPv4 路由进设备（`create_tun_dev.sh:103-110`）。easyss 自己的传输靠 `initDirectDialer` **绑定物理接口**（`client/client.go:167`）绕开 TUN，而 **tailcat 没有可绑定接口的公开 API**。因此：

- 若 magicsock 建了 UDP socket，它的出网 UDP 会被 TUN 捕获 → 进入 easyss 自己的 SOCKS5 → 形成环路（且语义错乱）。
- 开启 `relay_only=true` 后 magicsock 绑 `newBlockForeverConn()`，**不建任何 UDP socket**，唯一出口是到 DERP 主机的 TCP 连接。

**结论**：TUN 与 `relay_only=false` 不兼容。检测到 TUN 已开且 `relay_only=false` 时，记警告并在该会话内强制置 true。

> **实施修正（见 [12.9](#129-阶段-7-的实现记录) 第 29 条）**：这个强制只有在 tailcat 建 socket **之前**才真正生效（magicsock 在建 socket 时读这个开关）。因此启动路径（配置里已要求 TUN）在 `startVPN` 里强制为 true 并告警；运行期才打开 TUN 时改为**拒绝**并提示用户把 `vpn.relay_only` 打开后重启。另外只有 `peers` 非空时才强制/拒绝——没有对端就没有节点间直连，关掉 `relay_only` 只用 TUN 上网是合法组合。

### 8.2 DERP 不再需要绕行路由（原方案已删除）

原设计给 DERP 主机装 `/32` 主机路由，是因为 relay_only 下到 DERP 的 TCP 是 tailcat 唯一的出网通道，被 TUN 阶梯捕获就会绕回 easyss 自己。**DERP 私有化（3.3）后这一整类问题消失**：节点的 DERP 拨号目标是 `socks5://127.0.0.1:<入口端口>`，回环流量从不进 TUN 路由表，而真正的出网连接由 easyss 自己（已绑定物理接口）承担。

因此本版删除了 `vpn/node/bypass.go`、`Core.VPNBypassIPs`、`Config.BypassIPs` 与三个创建脚本的第 10/11 个位置参数。今天 TUN 下唯一需要关心的仍然是 8.1 那条：`relay_only=true`。

### 8.3 overlay 段的选择

`198.19.0.0/24` 已被 TUN 的 `128.0.0.0/1` 阶梯路由覆盖，**无需额外路由**。

不用 `100.64.0.0/10` 的原因：CGNAT 网段在物理接口上常存在 on-link 路由（比 TUN 的 `/1` 阶梯更具体），会**压过 TUN 路由**，导致 overlay 流量走物理网卡。`198.19.0.0/24` 属于 benchmarking 段，公网不路由，无此冲突。

> overlay 段本身**不需要与其他节点一致**（见 5.1）：它只在访问侧本地使用。

## 9. UDP 边界

- A↔B 单包上限 **1232 字节**（`tailcat.MaxUDPPayload`），超出丢弃；对端到目标不受此限。
- 每条 UDP 目标流对应一条隧道 UDP 流，空闲 2 分钟由 tailcat 回收（`DefaultUDPIdleTimeout`）。
- `relay_only=true` 时 UDP 也全部经 DERP。
- 适用场景：DNS（53）、QUIC 首包。**不适合**大包/高带宽 UDP。
- 本期不做带内分片；**ICMP 不承载**（见第 1 节非目标）。
- **对端面的 UDP 是本设计中唯一不能直接复用 `udpAssociate` 的地方**：`udpAssociate`（`socks5.go:450`）用 `net.ListenUDP(&net.UDPAddr{IP: tcpAddr.IP})` 绑定到对端的 **tailcat ULA**，而宿主没有这个地址，必然失败。因此对端面 UDP 走 `tailcat.Server.Listen("udp", ":<peer_port>")` + 薄中继，目标头同样遵循 5.1 的字面 loopback 契约。

## 10. 实现阶段

每个阶段独立可验证。

| 阶段 | 内容 | 验证 |
|---|---|---|
| **0** | 依赖与配置基座：`go get github.com/tailscale/tailcat@v0.7.0 && go mod tidy`；`config/vpn.go` 常量与归一化；`ServerProfile.DERP` + `DERPServer()`/`VPNDERPAddr()`/`VPNPeerPort()`/`VPNOverlayPrefix()`/`VPNRelayOnly()`；`server.vpn.derp_addr` 与 `ResolveDERPAddr()`；`vpn.NewConfig` 的校验；示例更新 | `go test ./config/... ./client/config/... ./server/config/... ./vpn/...`（派生、越界回退、`derp` 标记与回退 `servers[0]`、`derp_addr` 默认与覆盖、**短格式 peer 地址被拒**、服务端推导失败必须报错）；旧配置行为不变。**状态：已完成**（见 [12](#12-实施记录)） |
| **1** | 内嵌 DERP：`keys.go`、`derp.go`、`mount.go` + 服务端装配与 `Shutdown` 显式收尾（`region.go` 已在阶段 0 落地） | `/derp` 路由契约与 fallback 语义不变；密钥持久化后地址稳定；`region` 取 `derp_addr`；端到端零官方 DERPMap 请求 |
| **2** | 复用性打通：`Serve(net.Listener)`；`ProxyRuleDirect` 全直连；`overlay.go` | 自定义 listener 可用；overlay 分配稳定且无碰撞 |
| **3** | 对端面：`peerface.go`、`udprelay.go`、53 拦截开关 | 经隧道访问对端本地 echo；**域名与非 loopback 字面目标均被拒**；UDP 中继可用；自定义 `peer_port` 生效 |
| **4** | 访问侧 `routeVPN`：`route.go`、`clients.go` + 注入式改动（`route.go`/`socks5.go`/`udp.go`/`udp_pool.go` 四处） | 按 `host_name` 与 overlay IP 都能路由，且**隧道内 dst 恒为字面 `127.0.0.1:<port>`**；`VPN==nil` 时既有全部测试必须全绿。**状态：已完成**（见 [12.6](#126-阶段-4-的实现记录)） |
| **5** | 端到端与 `relay_only`：`relayonly.go`、`pathcheck.go`、client key 持久化与 nodekey 打印、`Core.startVPN/StopVPN`（`runner/vpn.go`）、CLI `-show-vpn-identity` | `relay_only` 生效（无直连路径）；进程内 DERP+对端面+访问侧端到端；**断言零官方 DERPMap 请求**；`allow_clients` 白名单可用；关闭时零 goroutine。**状态：已完成**（见 [12.7](#127-阶段-5-的实现记录)） |
| **6** | DNS 静态应答：`dns/forward.go` 钩子 + `dnsnames.go` | `b` 的 A 查询 → overlay IP；**AAAA 查询 → NOERROR 空应答**；非 peer 名不受影响。**状态：已完成**（见 [12.8](#128-阶段-6-的实现记录)） |
| **7** | TUN 透明访问：`bypass.go`（并集）+ 三个 `create_tun_dev*` 脚本 + `client/tun`/`tun_helper_*` 传参 + TUN 下 `relay_only` 强制 | 脚本层参数与路由幂等；跨 S 时并集覆盖两个 DERP 主机；真实 TUN 链路手工验收（需 root）。**状态：已完成**（见 [12.9](#129-阶段-7-的实现记录)） |
| **8** | 统计与文档：`stats` 计数器（5 处触点）+ README/AGENTS + 本文档同步 | `TestResetCounters` 不回归；文档与实际一致。**状态：已完成**（见 [12.10](#1210-阶段-8-的实现记录)） |

**收尾门槛**：`make lint` → `make verify` → 六平台 `make build` → 手工端到端（TUN 下 `ssh user@b`、非 TUN 下显式 SOCKS5、内网不可达、`ping b` 不通符合预期、`relay_only` 下无 UDP、4080 既有行为不变）。

> **收尾状态（阶段 8 完成时）**：`make lint`、`make verify`（`-race` 全量）与六平台 `make build` 全绿；非 TUN 的显式 SOCKS5 访问、内网不可达、`ping b` 不通、4080 既有行为不变这四项在阶段 4/5 的端到端用例里已被覆盖。**仍未做**的是需要真实部署的那两项：跨主机的真隧道与 TUN 下的 `ssh user@b`（需要一台有公网可信证书的 easyss 服务端 + root 权限）。

## 11. 风险与缓解

| # | 风险 | 缓解 |
|---|---|---|
| 1 | **gvisor 升级影响客户端 tun2socks**（tailcat 要求比仓库现有更新的 gvisor） | 最高风险。阶段 0 单独成一次可回滚提交并立即 `make verify`；若冲突，以 tailcat 要求版本为准并适配 `client/tun`，而非降级 tailcat |
| 2 | **TUN + tailcat 环路** | 8.1/8.2/8.3 三条前提共同消除；`pathcheck` 提供运行时自检 |
| 3 | **改动核心代理路径** | 可选注入隔离；以「`VPN==nil` 时既有全部测试全绿」作为阶段 4 硬验收（已达成，见 12.6） |
| 3b | **`decide()` 每次判定都查一次 overlay** | 命中路径是一次 `map` 查找（未命中再加一次 `netip.ParseAddr`）；相比判定本身（GeoIP/域名列表）可忽略 |
| 4 | **`relay_only` 依赖 `TS_DEBUG_ALWAYS_USE_DERP`** | 锁 tailscale 版本 + 启动告警（每次启动都打，含开关名）+ 文档写明退路。接线在 `vpnnode.ApplyRelayOnly`（见 12.7 第 22 条）。**注意 `vpn/node/pathcheck.go` 的 `PathStatus` 目前只有测试在用，"运行时自检"尚未接线**（见 12.11 第 40 条） |
| 5 | 对端面 UDP 不能复用 `udpAssociate` | tailcat UDP listener + 薄中继；阶段 3 单测覆盖 |
| 6 | **peer 地址误用短格式 → 拉官方 DERPMap** | 只设 `Server.Region`；`AssertFullAddr` 启动自检 + 配置校验拒收短格式 + 端到端断言零外部请求（4.7） |
| 7 | **`allow_clients` 配不起来**（client key 每次重启变化 / 无处查看） | client key 持久化（`<exe>/vpn/client.key`）+ 启动日志与 `-show-vpn-identity` 打印 `nodekey`。**已接线**（第 7 节第 3 条、4.4 的取值来源） |
| 8 | **跨 S 拓扑** | DERP 私有化（3.3）后跨 S 不再成立：节点只连得到自己那台服务端的回环 DERP。`vpnnode.assertPeersShareDERP` 在启动时拒绝不一致的 peer 地址 |
| 9 | **`peer_port` 自定义后对端需同步** | 文档与示例明确；默认值下零配置互通 |
| 10 | **N² 隧道开销**（访问方为每个对端一套 netstack+WireGuard） | 只连需要的对端；文档给出量级；后续若要收敛需引入 hub 转发（需 fork，本期不做） |
| 11 | UDP 单包 1232 字节 | 已声明适用场景 |
| 12 | **`relay_only=true` 时服务端成为带宽瓶颈** | 文档明确；非 TUN 场景需要吞吐时可关掉走直连 |
| 13 | **体积**：引用 tailcat 会把整个 WireGuard 引擎与 gVisor netstack 拖进二进制 | **已实测并解决**。单包时服务端 13.03 → 27.19 MiB（+109%）；按「是否引用 tailcat」拆成 `vpn` + `vpn/node` 后回到 **15.63 MiB**（+2.60 MiB，残留的是 `derpserver`/`tailcfg` 本身）。`vpn/deps_test.go` 用 `go list -deps` 钉住这条不变量，见 12.4 |
| 14 | **伪装面变化** | 公网上**没有**任何 DERP 路径：`/derp` 只对回环来源放行（3.3），非回环请求（含 `Upgrade: derp` 与非 GET 的 `/derp/probe`）一律得到伪装页面；其余路径语义与统计逐字节不变 |

## 12. 实施记录

### 12.1 阶段状态

| 阶段 | 状态 | 备注 |
|---|---|---|
| 0 | **已完成** | 依赖与配置基座；`vpn/config.go`、`vpn/region.go` 同时落地——阶段 0 的验收项（短格式 peer 地址被拒、`derp_addr` 校验、region 取 `derp_addr`）只有在这两个文件存在时才可能被测试，因此不属于阶段 1 |
| 1 | **已完成** | `keys.go`、`derp.go`、`mount.go`、服务端装配与 `Shutdown` 显式收尾。最强的验证是一条真实握手：把中继挂到 `httptest.NewTLSServer` 上，用与 `derphttp` 逐字相同的 `GET /derp` + `Upgrade: DERP` 请求，拿到 101 与正确的 `Derp-Public-Key`（`TestDERPServerUpgradeOverTLS`） |
| 2 | **已完成** | `Socks5Server.Serve(ln)`（`Start` 拆成 `bind` + `Serve`，监听器所有权下移到调用方）、`router.NewDirectOnly()`、`vpn/overlay.go` 的确定性分配。验证：`Serve` 在调用方 listener 上服务且 `Close` 不关它（调用方关掉才返回）、全直连路由器对任何目标都判直连且不拦 IPv6、overlay 分配与配置顺序无关且不落在网络/广播地址上 |
| 3 | **已完成** | `vpn/peerface.go`（tailcat Server + 隧道内 TCP/UDP 监听器）、`vpn/udprelay.go`（一次性目标头 + 薄中继 + 字面 loopback 拨号器）、`Socks5Options.DisableDNSIntercept`。**最强验证是真实隧道端到端**：进程内 DERP 中继 + 真实 tailcat 隧道，从客户端 `DialTCPPort` 进对端面再经其 SOCKS5 访问对端本机的 echo；域名（`localhost`）与非 loopback 字面目标均被拒；UDP 目标头同样只接受字面 loopback |
| 4 | **已完成** | `vpn/node/route.go`（`Route`：overlay/名字 → 对端，dst 恒归一化为字面 `127.0.0.1:<port>`）、`vpn/node/clients.go`（`ClientSet`：一对端一个 tailcat Client、共用持久化 client key）、`client/proxy` 的四处注入式改动。**最强验证是"看得见内层目标"的对端**：测试里起真实的 tailcat Server，隧道内跑一个最小 SOCKS5 服务端并用 `statute.ParseRequest` 直接读 CONNECT 目标，从而断言传输的目标**恰好**是 `127.0.0.1:<port>`（PeerFace 的拨号器只能拒绝非 loopback，区分不了 127.0.0.1 与 127.0.0.2）。另有与真实 PeerFace 的 TCP/UDP 互操作，以及 `VPN==nil` 全量回归 |
| 5 | **已完成** | `vpn/node/relayonly.go`（`ApplyRelayOnly` + `RelayOnlyEnvKnob`）、`vpn/node/pathcheck.go`（`Path`/`PathStatus`）、`runner/vpn.go`（`startVPN`/`StopVPN`/`LoadVPNIdentity`）、`Core` 接线、CLI `-show-vpn-identity`。**验证的四条硬验收**：① 端到端（进程内 DERP + 真实隧道 + 对端面 + 访问侧，按生产顺序组装）；② **零官方 DERPMap 请求**——官方 URL 是常量无法替换，因此改用可观测的等价证据：给 `ClientSet` 注入记录型 `DERPMapCache`，断言一次真实隧道访问之后它**零访问**（短格式地址必然先查缓存）；③ `allow_clients` 白名单用的是 `ClientSet` 从 `<exe>/vpn/client.key` 读出的那把 key；④ `StopVPN` 后 goroutine 回落到基线（并有"启动后必须升高"的前提校验，否则用例什么都没证明） |
| 6 | **已完成** | `client/dns` 的 `StaticNames` 钩子 + `vpn/node/dnsnames.go` 的 `ResolveStatic`（`Route` 的方法）。验证：A 就地应答且**不碰上游**（上游故意设为不可达）、AAAA 是 NOERROR 空应答、非对端名与其他 qtype 原样转发、`nil` 钩子下行为不变；名字比较忽略大小写并去掉根点 |
| 7 | **已完成** | `vpn/node/bypass.go`（并集 + 缓存）、三个 `create_tun_dev*` 脚本的第 10 个位置参数、`client/tun`/`proxy.TunConfig`/两个 `tun_helper_*` 的传参、`startVPN` 的 TUN 强制、`Core.CheckVPNTunCompat` 的运行期门禁。验证：linux/darwin/windows 三个脚本各自装出主机路由且失败会上报；并集覆盖本地 S 与全部 peer 内嵌 DERP；`relay_only` 三态下强制/保留；无对端时不强制。**未做**：真实 TUN 链路手工验收（需 root 与一台有公网可信证书的服务端） |
| 8 | **已完成** | `stats` 的五个 VPN 计数器（访问侧 TCP/UDP、拨号失败、静态名应答、对端面接受的流）与各自触点；README 新增"节点组网(VPN)"章节；AGENTS.md 补 `vpn`/`vpn/node` 目录、架构要点 15 与 `vpn.*` 配置说明 |

### 12.2 阶段 0 实测结论与对本文档的修正

| # | 本文档原文 | 实测 | 结论 |
|---|---|---|---|
| 1 | `server.vpn.derp_path`（默认 `/derp`） | 客户端侧 `derphttp.Client.urlString` 把路径**硬编码**为 `/derp`（`tailscale.com/derp/derphttp/derphttp_client.go:293`），`derphttp.NewRegionClient` 不暴露 URL 覆盖入口；`derpserver.Handler` 也文档化要求「mounted at /derp」并在内部分流**绝对路径** `/derp/probe` 与 `/derp/latency-check`（`derp/derpserver/handler.go:28`） | **删除该配置项**，固定为常量 `config.DefaultVPNDERPPath`（[4.1](#41-服务端derp-主机-s)、[4.3](#43-字段说明)） |
| 2 | 客户端 `applyDefaults` 派生 `peer_port`/`overlay_cidr`/`derp_addr` | `applyDefaults` 没有错误返回值，承载不了 4.7 那种必须报错的契约；且它在 `ApplySimpleOverrides`（`--local-port`）**之前**运行，写回会把派生值冻在旧 `socks_port` 上 | 改为访问器派生 + `vpn.NewConfig` 校验（[4.5](#45-归一化归属)） |
| 3 | `vpn/config.go` 的 `Normalize()` | 原始输入与已验证视图混在同一结构体上，「未配置」与「显式配置为默认值」无法区分 | 拆成 `Options`（原始）+ `Config`（已验证），入口 `NewConfig(Options)`（[第 6 节](#6-新增-vpn-包)） |
| 4 | 常量集中在 `config/types.go` | 仓库已有 `config/tun.go`、`config/timeouts.go` 的分域惯例 | 改为 `config/vpn.go`（[4.5](#45-归一化归属)） |
| 5 | 「`listen` 默认 `:443`」 | `buildHTTPServer` 直接把 `listen` 交给 `http.Server.Addr`，**没有运行期默认值**——留空时 Go 会监听 80 | 文档已更正；推导失败一律报错（[4.6](#46-derp_addr-与默认规则)） |
| 6 | （未预见）`listen: ":https"` | 服务名对 `net.Listen` 合法（Go 查表解析） | 推导经 `net.LookupPort` 归一化成**数字**端口：对端只会把它读成 `DERPPort int` |
| 7 | （未预见）`peers[].port` 的越界语义 | 若与本地 `peer_port` 各写一套规则，两处必然漂移 | 复用 `config.NormalizeVPNPeerPort`：未配置（0）或越界都取 `DefaultVPNPeerPort` |
| 8 | 「`servers[0]`」未说明与 `default` 标记的关系 | 跟随 `default` 标记会让「切换默认 server」静默改掉本节点对外通告的地址，而每个对端都要跟着改配置 | 明确：只看 `derp` 标记，否则 `servers[0]`，**不跟随 `default`**（[4.6](#46-derp_addr-与默认规则)） |

### 12.3 依赖与风险更新

- `github.com/tailscale/tailcat v0.7.0` 与 `tailscale.com v1.103.0-pre.0.20260916030321-a2263542f260` 已成为**直接依赖**，`vpn/region.go` 通过 `tailcat.ParseAddr` / `tailcat.Addr` 使用它。
- **风险 1 已解除**：`gvisor.dev/gvisor` 由 `v0.0.0-20260906120324-45bde0d1defa` 顶到 `v0.0.0-20260915211658-a6f909f08a72`，`go build ./...`、`go test ./...`（含 `client/tun` 全部测试）与 `make verify` 在新版本下全绿，`client/tun` 无需适配。
- **同一轮升级带来的唯一既有代码改动**：`golang.org/x/tools` 由 v0.49.0 顶到 v0.50.0，`modernize` 因此新增一条检查并命中既有代码 `server/handler/session.go:108`（`strings.LastIndexByte` → `strings.CutLast`）。已按新检查修正，与 VPN 逻辑无关。
- 新增的间接依赖包括 `github.com/tailscale/wireguard-go`、`golang.zx2c4.com/wireguard/windows`、`github.com/coder/websocket`、`github.com/gaissmai/bart`、`go4.org/netipx` 等。体积影响已实测并处理，见 12.4。
- 阶段 0 的测试面：`config`（`NormalizeVPNPeerPort`、`ParseVPNOverlayCIDR`、默认段与 CGNAT 不重叠）、`client/config`（`DERPServer` 的 `derp`/`servers[0]` 规则、`VPNDERPAddr` 含 IPv6 字面量、`VPNPeerPort` 跟随 `--local-port`、`relay_only` 三态与 JSON 往返、旧配置零影响）、`server/config`（`ResolveDERPAddr` 的推导/覆盖/失败路径、`LoadConfig` 只在 `vpn.enabled` 时校验）、`vpn`（region 往返自包含、`AssertFullAddr` 对短格式与缺 disco 公钥的拒绝、`NewConfig` 的全部校验）。

### 12.4 阶段 3 之后的包结构修正：`vpn` 与 `vpn/node`

设计 §6 原定单个 `vpn` 包。实测发现这会把整个 tailcat 引擎拖进**服务端**二进制，而服务端的 VPN 角色只需要跑 DERP 中继。量化结果（darwin/arm64，`-s -w`，与改动前的 HEAD 对比）：

| 二进制 | 改动前 | 单包 | 拆包后 | 阶段 5 后（客户端真正引用 `vpn/node`） |
|---|---|---|---|---|
| `easyss-server` | 13.03 MiB | 27.19 MiB（**+109%**） | **15.63 MiB（+2.60 MiB，+20%）** | 15.63 MiB（不变） |
| `easyss`（客户端） | 20.87 MiB | 20.89 MiB | 20.89 MiB | **27.79 MiB（+6.92 MiB）** |

根因用探针实测（只引用单个依赖的极简二进制）：只引用 `derpserver` 是 **6.46 MiB**，只引用 `tailcat` 是 **16.15 MiB**——即引用 tailcat 本身就要付约 10 MiB。

因此按「是否引用 tailcat」拆包：`vpn` 只放共享原语（DERP 中继、region、状态目录与密钥持久化），`vpn/node` 放节点自身的 VPN 栈。服务端二进制只依赖 `vpn`，回到 15.63 MiB；残留的 +2.6 MiB 是 `derpserver` 与 `tailcfg` 本身，属于必需成本。

客户端的 +6.92 MiB 小于探针测到的 ~10 MiB，因为客户端本来就有 gVisor（tun2socks 的 netstack），tailcat 只额外带来 WireGuard 引擎与 tailscale 的 magicsock/netmon 等。这是"客户端具备 VPN 能力"的必需成本：VPN 是配置驱动的运行期特性（`vpn.enabled`），不是构建标签，因此不能靠不链接来省掉。

`vpn/deps_test.go` 用 `go list -deps .` 把这条不变量钉住——注意是 `.` 而不是 `./...`，后者会把本来就该依赖 tailcat 的 `vpn/node` 一起算进来。

### 12.5 阶段 1-3 的实现中发现的问题

这些都**不是**设计的方向性错误，而是只有写出来才会暴露的实现陷阱，均已修正并被测试固定：

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 9 | `UDPRelay.Serve` 在监听器关闭时自己等待在飞流，而关掉那些流的 `Close` 要等 `Serve` 返回之后才被调用 | `PeerFace.Stop` 自锁到 UDP 空闲超时（实测 **2 分钟**） | `Serve` 不再等待在飞流（那是 `Close` 的职责）；`PeerFace.Stop` 的顺序固定为「关监听器 → 收 UDP 中继 → 等 Serve 循环 → 关 Socks5Server/Server」。回归测试 `TestUDPRelayCloseIsPromptWithActiveFlow` |
| 10 | UDP 空闲判定若按"每个方向各自计时"，且轮询粒度固定 15s | 单向流量（如只上报的 syslog）会被误杀；比 15s 更短的 `idle` 形同失效，回收比配置晚一个数量级 | 两个方向共用一个活动时间戳；轮询间隔取 `min(idle, 15s)` |
| 11 | 拨号器与 UDP 目标头曾用 `net.LookupPort` 解析端口 | 服务名（`127.0.0.1:http`）被接受，于是同一份配置在不同机器上会拨到不同端口 | 只接受数字端口（`strconv.Atoi`），拒绝任何服务名 |
| 12 | `tailcat` 在**编码**地址时会抹掉 region 编号、**解析**时按序号补回（第一个 region 补成 1） | 一个 `RegionID` 为 0 的 region 会产出一份看起来完全正常、实际与本机对不上的地址；真正的失败点是 `tailcat.Server.Start` 的 "missing RegionID"，错误信息不指向配置 | `NewPeerFace` 在构造期校验 region（`RegionID` 非零、至少一个节点且带 HostName）；出处是 `ConnInfo.Addr`/`ParseAddr` |
| 13 | 对端面必须关掉 53 端口拦截 | 否则对端本机监听在 53 的服务（如 systemd-resolved）无法通过 VPN 访问，且被拦截的流量会按"查询域名"重新分流，与"只拨字面 loopback"的契约冲突 | 新增 `Socks5Options.DisableDNSIntercept`（默认 false，即既有行为不变） |

### 12.6 阶段 4 的实现记录

设计 §5.3 只列了"三处注入式改动"。写出来之后有两处必须修正，都是 5.1 的"端口互通"目标与既有公网策略语义相撞的结果：

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 14 | `VPNRoute` 接口若定义在 `vpn/node`，`client/proxy` 就必须导入它 | 导入环：`vpn/node` → `client/proxy`（对端面复用 `Socks5Server`），反向再依赖即无法编译 | 接口定义在消费方 `client/proxy/route.go`；`vpn/node` 的 `Route` 实现它。这也是 Go 的惯例（接口属于使用它的包） |
| 15 | 设计的注入点是 `handleRegularUDP`，但 `handleUDP` 在它之前还有三道门禁 | `disable_quic=true` 会**静默吞掉**发往对端 443 的数据报；53 端口会被 DNS 拦截器接管并按"查询域名"重新分流；TCP 侧同理（`connectHandler` 的 53 拦截在路由之前）。三者都直接违背"节点之间服务端口互通"这一原始诉求 | UDP 的对端判定上移到 `handleUDP` 的**所有门禁之前**（对端名与 overlay IP 本来就不是公网目标，这些策略与它们无关）；TCP 侧在 53 拦截之前判对端。既有行为在 `VPN==nil` 时逐字节不变 |
| 16 | 会话池的 `acquireDirect` 只有一个 `Dial` 钩子 | VPN 路径若复制一份池，就要同步维护上限驱逐、singleflight 去重、空闲回收三套逻辑 | `acquireDirectWith(key, dst, dial)`：按会话给出拨号函数。这样 VPN 只是"换一个拨号器"，会话形状与直连完全一致 |
| 17 | 内层握手若不给截止时间 | 一个卡住的对端面会让这条流永远停在握手里（`DialTCPPort` 的 ctx 只约束拨号） | 握手期间设 deadline，**握手后立刻清掉**——否则长连接的 SSH 会话会在那个绝对时刻被无声切断 |
| 18 | `targetHeaderConn` 若把头单独写成一个数据报 | 对端面按"每条流第一个数据报解出目标"处理（`DecodeUDPTarget`），分开写会多一次空转，且该数据报一旦丢失，这条流就永远停在"没有目标" | 头与首个载荷合并在**同一条**数据报里；`TestTargetHeaderConnPrependsOnce` 固定字节语义（含"返回值必须是载荷长度"） |
| 19 | 访问侧的错误信息里若带上 `PeerRef.Address` | 该地址内嵌 preshared key，等价于对端面的接入凭据（第 7 节），会随日志扩散 | 错误信息只带 `host_name`；`DialTCP` 里的地址不落日志 |

阶段 4 的测试面：`client/proxy`（判定顺序、TCP 注入、UDP 注入与回包组帧、443/53 门禁让路、`VPN==nil` 全量回归）、`vpn/node`（内层目标恰为字面 `127.0.0.1`、名字与 overlay IP 两条路径、与真实对端面的 TCP/UDP 互操作、坏目标在拨号前被拒、client key 跨重启稳定、`Close` 后拒绝新拨号）。`make lint` 与 `make verify`（`-race` 全量）全绿。

### 12.7 阶段 5 的实现记录

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 20 | tailcat 的地址往返会**抹掉 region 编号与 region code**，解析时按序号补回（第一个 region → `RegionID=1`、`RegionCode="1"`），节点名也补成 HostName | 访问侧看到的 region 永远是 `1/"1"`，而不是本节点配置的 `vpn.RegionID=901`；`PathStatus` 的日志因此显示 `via DERP(1)`。这**不影响中继选择**：一份地址只带一个 region，两端各自在自己的 DERPMap 里解析对端与 HomeDERP，且都连到地址里内嵌的同一个 `host:port`（真正决定位置的是 HostName/DERPPort，它们原样保留） | 不改（改了反而与 tailcat 的实际行为脱节）；用 `TestPeerAddressRegionNumberIsRewritten` 把"编号被改写、位置被保留"两件事同时钉住，并在 2.1 的同一机制下记录 |
| 21 | `-show-vpn-identity` 最初经 `vpnnode.NewConfig` 推导地址 | 该函数会校验 `peers[]`，而运维第一次跑这条命令时 `peers` 往往**正是空的**（他们要先拿到对端地址才能填）——命令在最需要它的场景下报"地址不可用" | 节点地址是 `(身份, derp_addr)` 的函数，与 peers/overlay/peer_port 无关，因此直接用它推导；`LoadVPNIdentity` 的用例里加了一条"peer 地址写坏也不影响地址"的断言 |
| 22 | `relay_only` 的开关是 tailscale 的**进程级** `envknob`，且默认缺省为 false | ① 无法"只对某个对端强制中继"；② 同一个进程先后跑两次会话时，上一次留下的 `true` 会让下一次的 `relay_only=false` 静默失效 | `ApplyRelayOnly` **显式写 true 与 false**；调用点在 VPN 栈构造处（任何 tailcat Server/Client 启动之前），并在启动日志里明确打出这个 `TS_DEBUG_` 开关名（`TestApplyRelayOnlyWritesBothValues` 固定） |
| 23 | 官方 DERPMap 的 URL 是 tailcat 的**常量**（`DefaultDERPMapURL`），无法在测试里替换成一个记录型服务器 | "断言零官方 DERPMap 请求"没有直接可观测的接口 | 改用**等价且可观测**的证据：给 `ClientSet` 注入记录型 `DERPMapCache`。地址是短格式时 `ConnInfo.Expand` 必然先查缓存（再回退官方 URL），因此"缓存零访问"等价于"没有进入取 DERP map 的代码路径" |
| 24 | 设计的阶段表里写了 `App.Start/Stop` | 看起来需要在 `cmd/easyss` 里再加一层启停 | **无需改动**：托盘/headless 的三条启动路径本来就统一走 `runner.Run` / `Core.Stop`，VPN 挂在 `Core` 上即自动随会话启停。这也让 `-show-vpn-identity` 成为本期唯一的 CLI 面 |
| 25 | `startVPN` 的三份状态文件（两份密钥 + `peer.txt`）都写在"可执行文件旁边" | 测试若直接用默认路径会污染测试二进制所在目录 | `runner/vpn.go` 的 `vpnPaths` 是显式参数（生产取 `vpn.*Path()`），测试注入 `t.TempDir()` |

阶段 5 的测试面：`vpn/node`（端到端 + 零 DERPMap 访问、`relay_only` 下无直连路径且隧道仍可用、白名单用持久化 client key、region 编号改写、`Path.String`）、`runner`（组装与幂等拆卸、三份状态文件落盘、`peer.txt` 是完整格式、**关闭后 goroutine 回到基线**（含"启动后必须升高"的前提校验）、身份输出两半与降级、`vpn.derp_addr` 缺失必须报错）。

**手工冒烟（真机、headless 客户端、`vpn.enabled=true`）** 覆盖了自动用例覆盖不到的东西：

- 日志按预期出现 `[VPN] relay_only is on: ...TS_DEBUG_ALWAYS_USE_DERP...`、`[VPN] peer face listening peer_port=6090`，且对端面的 TCP/UDP 监听地址是**隧道内的 ULA**（`fd7a:115c:a1e0:...`），宿主上看不到这两个端口；
- `[VPN] node identity ready` 打出了 `address` / `address_file` / `client_nodekey` / `relay_only` / `peers`，以及每个对端的 `overlay_ip`（`a → 198.19.0.15`，即 `overlay_cidr` 的确定性分配）；
- `<exe>/vpn/{client.key,node-identity.json,peer.txt}` 三份文件都是 0600；
- `-show-vpn-identity` 与 `-show-config-example` 的输出可直接互相喂：用示例配置跑前者能正常给出两半；
- `SIGTERM` 后 `[EASYSS] stopped` 且进程干净退出（VPN 随 `Core.cleanup` 一起收尾）。

未做（需真实部署，属收尾门槛）：跨主机的真隧道（需要一个有公网可信证书的 easyss 服务端做内嵌 DERP），以及 TUN 下的透明访问与 `ssh user@b`。

### 12.8 阶段 6 的实现记录

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 26 | 静态名钩子若定义在 `vpn/node`，`client/dns` 就必须导入它 | `vpn/node` → `client/proxy` → `client/dns` 已经成链，反向依赖即导入环 | 与阶段 4 的 `VPNRoute` 同一处理：接口 `dns.StaticNames` **定义在消费方** `client/dns`，由 `vpn/node.Route`（方法 `ResolveStatic`）实现。`NewForwardServer` 多一个 `static StaticNames` 参数，`nil` 表示钩子关闭 |
| 27 | 问题名（`dns.Question.Name`）总是带根点，而配置里的 `host_name` 是人类书写形式 | 直接比较永远不命中，表现为"TUN 下 `ssh user@b` 解析不到" | `ResolveStatic` 先去掉一个末尾的根点再查（`overlay.Addr` 本身不区分大小写）。只去一个点，`b.lan` 这类含点的名字仍然能匹配 `b.lan.` |
| 28 | 静态应答的 TTL | overlay 地址虽由公钥确定性派生，但**槽位是线性探测分配的**：增删一个对端就可能让别的对端换地址。TTL 太长会让解析器缓存里的旧地址指向另一个对端 | 取 60 秒（`dns.StaticNameTTL`）：地址是"改了配置就该重启"的东西，短 TTL 把这个窗口压到一分钟 |
| 36 | 设计 2.5 断言"TUN 模式把系统 DNS 指向 easyss 的本地转发服务器"，因此把钩子挂在 `client/dns/forward.go` 就够 | **前提不成立**：`session.tunConfig` 交给 TUN 的是 `tunDNS()`，即 `PreferredSystemDNS()`——一个**公网**解析器（如 223.5.5.5）。它的查询经 TUN 到达 tun2socks，再以 53 端口进入 **`client/proxy` 的 DNS 拦截器**；`client/dns` 的转发服务器只在 `enable_forward_dns=true`（路由器/软路由把 LAN 设备的 DNS 指过来）时才运行。照原设计实现，TUN 下 `ssh user@b` 依然解析失败（上游返回 NXDOMAIN） | 在**两个前端**上都接钩子，并把应答语义收敛到一处 `dns.StaticReply`（A → overlay IPv4、AAAA → NOERROR 空应答、其余原样转发），避免两份实现漂移。代理侧沿用**同一个注入点**：`Socks5Options.VPN` 的注入面可选地实现 `ResolveStatic`（`client/proxy.VPNStaticNames` 是 `VPNRoute` 的可选扩展），因此 runner 不需要第二个必须与 VPN 保持同步的字段 |

阶段 6 的测试面：`client/dns`（不碰上游的就地应答、AAAA 空应答、非对端名与其他 qtype 转发、`nil` 钩子下行为不变、静态应答计数器）、`client/proxy`（`plan` 判定为静态动作、UDP 与 TCP 两个前端都把应答写回且 Id 一致、非对端名与其他 qtype 不被就地应答、可选能力缺席时返回 nil）、`vpn/node`（大小写与根点归一化、未命中与空名、相邻 overlay 地址不算命中、未装配的 `Route` 不 panic）。

> §12.7 末尾那句"未做"仍然成立：**跨主机的真隧道与 TUN 下的 `ssh user@b` 需要真实部署**（一台有公网可信证书的 easyss 服务端 + root）。阶段 6-7 交付的是这两条路径的代码、参数契约与可自动化的验收项。

### 12.9 阶段 7 的实现记录

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 29 | 设计写的是"检测到 TUN 已开且 `relay_only=false` 时记警告并在该会话内强制置 true" | 这个"强制"只在 tailscale 读开关之前有效：magicsock 是在建 socket 时读 `TS_DEBUG_ALWAYS_USE_DERP` 的，VPN 栈一旦启动就已经绑好 UDP socket，之后置 true 对它们无效——照字面实现会得到一个"看起来强制了、实际没生效"的假象 | **拆成两条路径**：启动时（`startVPN` 的 `tunWanted`，早于任何 tailcat 组件）真正强制为 true 并告警；运行期（托盘打开 TUN、helper 路径）由 `Core.CheckVPNTunCompat` **拒绝**，错误信息直接告诉用户把 `vpn.relay_only` 打开并重启。另外只有存在对端时才拒绝：`peers` 为空时不存在节点间直连，用户把 `relay_only` 关掉、只用 TUN 上网是合法组合 |
| 30 | 绕行路由要装在哪里、谁来装 | 三个创建脚本此前只收到 `local_gateway`（linux/darwin）或连网关都没收到（Windows），而绕行路由的下一跳只能是物理网关 | linux/darwin 复用已有的第 4 个参数；**Windows 新增第 11 个参数**（物理网关），因为它的脚本此前完全不需要这个值。列表是第 10 个参数（空格分隔的单个实参），三平台脚本各自按空白拆开逐个安装 |
| 31 | cmd.exe 没有 `%10`（`%10` 是 `%1` 后接一个字面 `0`） | Windows 脚本会**静默丢参数**：绕行列表根本取不到，而脚本仍以 0 退出 | 脚本用 9 次显式 `shift` 取到第 10、11 个实参（不用 `for` 里的 `shift`：它在批处理上下文里的作用域不可靠）。测试固定"第 10/11 个参数真的到达脚本"，覆盖原有 9 参数调用（shift 后为空 → 跳过绕行步骤） |
| 32 | 只支持 IPv4 绕行（脚本按 `/32` 安装） | 一个只解析出 AAAA 的 DERP 主机无法绕行，那条连接会被 TUN 捕获 | 明确取舍并**告警**（`Bypass` 丢弃 IPv6 并打日志），不静默漏掉。理由：三平台脚本参数按 `/32` 设计，而 Windows 的 IPv6 主机路由需要物理接口名（`netsh interface ipv6 add route` 不接受网关），为一个当前部署形态用不到的边角再传一个平台相关的参数不划算 |
| 33 | 绕行路由在关闭脚本里删除吗 | 删要再改三个关闭脚本；不删则留下一批指向**物理网关**的 `/32` | 不删。这些路由的下一跳就是物理网关，TUN 关闭后它们与默认路由同向，不可能黑洞流量（与"残留的分流路由 = 全机断网"是两回事）。这一点写在 `client/tun.Config.BypassIPs` 的注释里 |
| 34 | `Bypass` 的解析时机 | 每次打开 TUN 都解析一遍对端 DERP 主机；一次临时解析失败会让该主机的绕行路由缺失（"TUN 打开后某个对端连不上"这种极难排查的故障） | 带 TTL（10 分钟）的实例级缓存，且在重新解析失败时**退回上一次的结果**并告警；本地 S 优先用 `Core.publishServerIPs` 的预解析结果（既有权威答案，也不再在系统 DNS 即将被改写时查询） |
| 35 | 解析失败的作用域 | 一个对端的 DERP 主机暂时解析不出来，不应该让整个 TUN 起不来 | `Bypass.IPs` **不返回错误**：解析不了的主机被跳过并逐条告警，其余主机的绕行路由照常安装 |

阶段 7 的测试面：`vpn/node`（并集覆盖本地 S 与多个对端、预解析结果优先于解析、字面 IP 不查 DNS、缓存与去重、单点失败不影响其余、IPv6 被丢弃并告警、坏 peer 地址被跳过）、`runner`（TUN 下强制 `relay_only` 且开关真的被写入、无对端/无 TUN 时不强制、`VPNBypassIPs` 的并集、`CheckVPNTunCompat` 的四种组合与 nil 核心）、`client/tun`（第 10 个实参与 `osascript` 的引号处理）、`cmd/easyss`（linux/darwin 脚本的绕行路由与"被拒绝必须上报"、空列表不装路由；Windows 脚本的 shift 取参与同样的断言）。

### 12.10 阶段 8 的实现记录

统计只加了五个计数器，每个都对应一个"用户会问为什么"的问题（见 `stats.RecordVPN*`）：

| 计数器 | 触点 | 回答的问题 |
|---|---|---|
| `vpn_tcp_streams` | `vpn/node.Route.DialTCP` 成功之后 | 经隧道打开了多少条对端 TCP |
| `vpn_udp_flows` | `vpn/node.Route.DialUDP` 成功之后 | 同上（UDP 流） |
| `vpn_dial_errors` | `DialTCP`/`DialUDP` 的失败分支 | 用户看到的"连不上"有多少次 |
| `vpn_dns_static_answers` | `client/dns.ForwardServer.staticReply` 命中时 | 对端名字是否真的走了本地应答（而不是被上游 NXDOMAIN 吞掉） |
| `vpn_peer_face_streams` | `peerface.countingListener.Accept` 与 `UDPRelay.Serve` | 本节点被访问了多少次（对端面 TCP+UDP 合计） |

两个取舍：

- **对端面 TCP 用 `countingListener` 计数**：对端面的 TCP 服务复用的是 `proxy.Socks5Server`，它没有"接受了一条流"的回调，而在监听器层计数正是"对端面自己拥有的对象"。
- **快照字段带 `omitempty`**：`vpn.enabled=false` 时五个计数器恒为零，不应在既有 `/stats` 输出里多出五个 `0` 字段（既有的服务端计数器也是这个惯例）。

阶段 8 的测试面：`stats`（`TestResetCounters` 覆盖新计数器，不回归）、`client/dns`（静态应答计数 +1）、`vpn/node`（一次真实端到端 TCP 访问让两个计数器各 +1、失败数为零；一次真实 UDP 流让 UDP 计数器 +1）。

### 12.11 DERP 私有化与随之而来的简化

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 37 | DERP 挂在公网 HTTPS 上（`/derp`），只靠"是否带 Upgrade 头"分流 | 任何知道域名的人都能连上并把它当免费中继（`derpserver` 不设客户端校验、无限速、无连接上限），`POST /derp/probe` 还会拿到一行 derpserver 独有的文案 | DERP 私有化：节点侧交给 tailcat 一个拨号器（`DERPDialer`）把 DERP 连接放进 easyss 隧道 → 服务端改拨自己的回环监听；`vpn.NewDERPMount` 只对回环来源放行（3.3）。按 `ALL_PROXY` 实现的第一版**不生效**（tailcat 关掉了 netns），已由拨号器取代 |
| 38 | 需要为 DERP 主机装 TUN 绕行路由（8.2） | 每个 DERP 主机一条 `/32`、三个脚本各加参数（Windows 还要 shift 9 次）、`Bypass` 的 TTL 缓存与"退回上次结果" | 整块删除：回环入口不进 TUN 路由表。`vpn/node/bypass.go`、`Core.VPNBypassIPs`、`Config.BypassIPs`、脚本第 10/11 个参数与相关测试全部退役 |
| 39 | 跨 S（peer 通告另一台 DERP）在私有化后不可达 | 表现为第一次访问对端时隧道拨号超时，排障成本高 | `vpnnode.assertPeersShareDERP`：启动时校验每个 peer 地址内嵌的 DERP 主机与本节点一致，不一致直接报错并说明"单一 S" |
| 40 | `relay_only` 的失效无法观测 | tailscale 若改名 `TS_DEBUG_ALWAYS_USE_DERP`，`envknob.Setenv` 只会静默写一个没人读的变量 | 未接线：`PathStatus` 仍只有测试调用。作为替代，`runner/derpshim_test.go` 的 `TestTailcatDERPDialsUseAllProxy` 用子进程守卫 `ALL_PROXY` 钩子本身（tailscale 改拨号路径会红）；relay_only 的运行期自检仍待接 |

本版还顺手修掉了评审中发现的三处缺陷：`overlay_cidr` 缺下界（`0.0.0.0/0` 会让槽位表申请约 4 GiB）、VPN UDP 会话键缺端口（同一对端两个端口会串包）、`config.SplitDERPAddr` 的三返回值签名破坏 Android AAR 的 gobind 绑定（`make easyss-android-aar` 曾在 CI 直接失败）。

### 12.12 DERP 拨号器：从环境变量改为 fork 提供的公开选项

| # | 问题 | 后果 | 修正 |
|---|---|---|---|
| 41 | `ALL_PROXY` 方案在 tailcat 上根本不生效 | tailcat 的 `createEngine` 调用 `netns.SetEnabled(false)`，`netns.NewDialer` 因此返回未包装的普通拨号器；节点会直连 `/derp`，而服务端只放行回环来源 → VPN 完全不可用。当时的测试只验证了 netns 层（直接调 `netns.NewDialer`），属于假阳性 | 改为 tailcat 的 `DERPDialer` 选项：`runner/derpdialer.go` 用 `net.Pipe` + `StreamHandler.OpenTCPStream` 把中继式接口适配成拨号器；顺带删掉入口端口派生、`ALL_PROXY` 读写与平台守卫（`derp_env_*.go`） |
| 42 | `relay_only` 依赖调用方去写 tailscale 的进程级调试开关 | 开关名一变就静默失效；调用方还得自己保证"在任何 tailcat 组件之前"这个顺序 | tailcat 增加 `DERPOnly` 选项，由它在 `createEngine` 里、创建引擎之前写；`vpnnode.ApplyRelayOnly`/`RelayOnlyEnvKnob` 删除 |
| 43 | 上游没有"给 DERP 连接指定拨号器"的入口 | `derphttp.SetURLDialer` 只对 URL 模式生效，而 magicsock 用的是 region 客户端 | 两个 fork（分支 `easyss/derp-dialer`）：tailscale 侧 `derphttp.SetDialer` + region 客户端支持 + `magicsock.Options.DERPDialer` + `wgengine.Config.DERPDialer`；tailcat 侧 `Server`/`Client` 的 `DERPDialer`/`DERPOnly`。`go.mod` 用 `replace` 指向同级 fork，上游接受后再删 |

验证：`TestRegionClientUsesInjectedDialer`（tailscale，region 客户端确实用了注入的拨号器）、`TestClientCarriesDERPOptions`/`TestServerCarriesDERPOptions`（tailcat，选项落到后端且 DERP-only 在引擎之前生效）、`TestDERPDialerCarriesTheConnectionOverTheTunnel`（easyss，拨号器把连接送进隧道、隧道断开时连接结束）、`TestVPNNodeUsesTheInjectedDERPDialer`（真实隧道里对端面与访问侧**双方**的 DERP 连接都经注入的拨号器）。

## 附录 A：实测依据

### A.1 tailcat v0.7.0

| 结论 | 位置 |
|---|---|
| 客户端不接受入站 | `tailcat.go:1957`（`return nil, true // don't accept any incoming connections to client`） |
| 节点 ULA 派生 | `tailcat.go:1755` `tcAddrForKey` |
| UDP 上限 | `tailcat.go:554` `MaxUDPPayload = 1232` |
| 对端转发入口 | `tailcat.go:697` `return s.OnTCPForward(dst), true` |
| Server API 面 | `listen.go:36` `func (s *Server) Listen(...)`；无 dial 方法 |
| 地址自包含 / 长短格式 | `ConnInfo.Addr()` / `ParseAddr` / `Addr.Resolve`（`tailcat.go:991` 起；`Resolve` 文档说明「未内嵌 region 时需查 DERPMap」） |
| 默认 DERPMap URL | `tailcat.go:106` `DefaultDERPMapURL = "https://tailcat.dev/derpmap.json"` |
| server key 的保存与 `--client` 语义 | `cmd/tailcat/genkey.go`（`genkey --client` 打印客户端公钥供 `--allow` 使用） |

### A.2 tailscale.com v1.103.0-pre

| 结论 | 位置 |
|---|---|
| 强制走 DERP 的开关 | `wgengine/magicsock/debugknobs.go:37` `debugAlwaysDERP = envknob.RegisterBool("TS_DEBUG_ALWAYS_USE_DERP")` |
| 开关生效点（不建 UDP） | `wgengine/magicsock/magicsock.go:3706` `if debugAlwaysDERP() { ... newBlockForeverConn() ... }` |
| 运行期可设 | `envknob/envknob.go:94` `func Setenv(envVar, val string)` |
| DERP 服务端可作为库 | `tailscale.com/derp/derpserver`：`New` / `Handler` / `Close` / `ModifyTLSConfigToAddMetaCert` |
| DERP 路径**硬编码**为 `/derp` | `derp/derphttp/derphttp_client.go:293` `urlString` → `fmt.Sprintf("%s://%s/derp", proto, host)`；且 `magicsock` 用的是 `derphttp.NewRegionClient`（`wgengine/magicsock/derp.go:399`），不经过可传 URL 的 `NewClient`，因此没有覆盖入口 |
| `derpserver.Handler` 要求挂在 `/derp` | `derp/derpserver/handler.go:28` 按**绝对路径** `/derp/probe`、`/derp/latency-check` 分流；函数注释即「to be mounted at /derp」 |
| DERP 客户端走 HTTP/1.1 Upgrade | `derp/derphttp/derphttp_client.go`（WebSocket 仅在 `TS_DEBUG_DERP_WS_CLIENT` 下） |

### A.3 当前仓库

| 结论 | 位置 |
|---|---|
| TUN 只有一个 SOCKS5 出口 | `client/tun/tun.go:312` |
| TUN 路由阶梯 | `scripts/create_tun_dev.sh:103-110` |
| TUN 设置系统 DNS | `client/tun/tun.go:649` |
| 直连拨号器绑定物理接口 | `client/client.go:167` |
| 路由判定（可全直连） | `client/router/router.go:326-327` |
| 直连拨号无 LAN 拒绝 | `client/proxy/socks5.go:403` `directTCPConnect` |
| UDP associate 绑本地地址 | `client/proxy/socks5.go:450` `udpAssociate` |
| 53 端口被 DNS 拦截 | `client/proxy/socks5.go:329-331`（`if port == "53" { handleTCPDNS }`） |
| 端口派生惯例 | `client/config/build.go:80-81`、`:111-113`（`http_port = socks_port + 1000`） |
| 服务端配置无 `port`，端口在 `listen` | `server/config/config.go:45-52`、`ExampleConfig()` 的 `Listen: ":443"` |
| DNS 转发入口（LAN/`enable_forward_dns`） | `client/dns/forward.go` `handleDNS` |
| TUN 模式 DNS 的实际入口（公网解析器的查询经 tun2socks 以 53 端口到达） | `client/proxy/dns.go` `dnsInterceptor.plan` |
| 两条 DNS 路径共用的静态名应答 | `client/dns/static.go` `StaticReply` |

## 附录 B：术语

| 术语 | 含义 |
|---|---|
| 对端节点 / peer | 你想访问的那个 easyss 节点（B） |
| 对端面 / peer face | 对端节点在 tailcat 隧道内提供的 SOCKS5 服务（只接受字面 loopback 目标） |
| 访问侧 | 发起访问的节点（A） |
| DERP 中继 S | 提供内嵌 DERP 的 easyss 服务端 |
| overlay IP | 访问侧**本地**给对端分配的虚拟 IPv4（`198.19.0.0/24`），仅用于 TUN 模式的 DNS 应答与路由匹配；不进隧道、不需要跨节点一致 |
| peer_port | 对端面在隧道内的端口（默认 6080），**不在宿主上监听** |
| 内层 CONNECT | 访问侧经隧道发往对端面的 SOCKS5 请求；按契约其 dst 恒为字面 `127.0.0.1:<port>` |
| 完整格式地址 | 内嵌 DERP 节点详情的 tailcat 地址；与之相对的短格式只带 region ID、会触发官方 DERPMap 查询 |
