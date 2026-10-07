# AGENTS.md — Easyss v3

## 项目概述

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，客户端+服务端架构。

## Go 环境

- 模块路径：`github.com/nange/easyss/v3`（根模块原地升级，不维护 v2/v3 双模块）
- Go 版本：`1.27.2+`（go.mod）

## 核心目录结构

```
cmd/easyss/         客户端入口，含系统托盘(systray) UI（nange/systray 分支，纯 Go 零 CGO）
cmd/easyss-server/  服务端入口，单文件 main.go
client/             客户端核心：Client 结构体
client/config/      客户端配置（JSON 解析、v2→v3 迁移）
client/router/      GeoIP + 域名列表路由引擎
client/dns/         DNS 转发服务器 + freecache 双缓存
client/proxy/       SOCKS5/HTTP 代理服务器 + StreamHandler
client/tun/         TUN2socks 虚拟网卡 + ICMP 代理
vpn/                节点组网共享原语（**不引用 tailcat**，服务端只依赖它）：内嵌 DERP 中继、region、状态目录与密钥持久化
vpn/node/           节点自身的 VPN 栈（**引用 tailcat**）：身份、overlay、对端面、访问侧、pathcheck
server/             服务端核心：Server 结构体（TLS/certmagic）
server/config/      服务端配置类型
server/handler/     TCP/UDP/ICMP 请求处理 + fallback 伪装页面
server/handler/assets/fallback/  fallback 模板/CSS/内容（//go:embed：template.html + themes.json + content.json）
server/nextproxy/   上游 SOCKS5 代理（动态 IP/域名学习）
transport/          传输层抽象：Transport/Stream 接口
 transport/http2/    HTTP/2 传输实现（uTLS Chrome 指纹，least-active 槽位调度，懒加载扩容）
protocol/           应用帧协议：HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER 编解码
crypto/             加密层：PBKDF2 KDF + HKDF key 派生 + 计数器 nonce AEAD（两阶段）
shaper/             流量整形：分桶 padding + cover traffic 注入 + 批处理
relay/              双向中继：Bidirectional(idleTimeout, src→dst, dst→src)
stats/              全局原子计数器 + 快照（streams/bytes/RTT/DNS hits 等）
config/             共享常量（默认端口、端点路径、buffer 大小等）
log/                基于 slog 的日志，默认时区 Asia/Shanghai
util/               工具函数（网络、文件、DNS、系统命令）
util/bytespool/     字节缓冲池（2 的幂次分配器，最大 128KB）
assets/             嵌入的 GeoIP 数据库 + 直连/屏蔽域名列表
scripts/            各平台 TUN 设备脚本（//go:embed，按 GOOS 自动选择）
pprof/              可选 pprof HTTP 服务（127.0.0.1:6060）
icon/               平台特定托盘图标（darwin/linux/windows）
version/            构建版本信息（GitTag、BuildDate 等）
```

## 构建命令

### 本机开发（产物写在 `bin/` 根目录）

```bash
# 客户端 (Linux/Mac)
make easyss

# 客户端 (Windows)
make easyss-windows

# 服务端
make easyss-server

# 服务端 (Windows)
make easyss-server-windows

# Android AAR — 需要 JDK(javac)、Android SDK/NDK 和 gomobile/gobind：
#   go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
#   （gomobile 通过 PATH 查找 gobind；Makefile 依次按 PATH → GOBIN → GOPATH/bin 定位 gomobile）
make easyss-android-aar

# 无系统托盘版本 (headless/Android)
make easyss-headless
```

### CI / 发布（产物写在 `bin/<os>-<arch>/` 子目录）

每个平台一个目录，不同架构不会互相覆盖，因此打包与构建顺序无关：

```bash
make build            # 全部 6 个平台的二进制：linux/windows/darwin × amd64/arm64
make pack             # build + 14 个 zip 资产（落在 bin/）
make dist             # 发布资产：pack + Android AAR（CI 的 release/nightly 用它）
make verify           # lint + test-race（发布前的显式校验）
make clean            # 只清 CI 产物；bin/ 下的本机二进制、config.json、日志不动

# 单平台
make build-linux-amd64   # bin/linux-amd64/{easyss,easyss-headless,easyss-server}
make build-linux-arm64
make build-windows-amd64 # bin/windows-amd64/{easyss.exe,easyss-server.exe}
make build-windows-arm64
make build-darwin-arm64  # bin/darwin-arm64/{Easyss.app,easyss-server}
make build-darwin-amd64
```

zip 资产名（`easyss-linux-amd64.zip` 等）与 zip 内的二进制名是客户端自更新
（`selfupdate/product.go`）与 `docker/Dockerfile` 的对外契约，改动会导致老客户端
无法自更新，不要重命名。

> `.PHONY` 只是 Makefile 的声明行。不要用 `make .PHONY` 当目标——它会把
> format/lint/test/全部构建当作前置目标跑一遍，这正是旧 CI 里重复构建的来源。

### 交叉编译示例

```bash
# Linux ARM64 headless 客户端 / 服务端
make build-linux-arm64

# macOS ARM64 / Intel 客户端与服务端（含 .app bundle）
make build-darwin-arm64
make build-darwin-amd64

# 一次性本机交叉构建仍可用（产物落在 bin/ 根目录，会被后面的构建覆盖）
GOOS=linux GOARCH=arm64 make easyss-headless
```

## 运行单个测试 / lint

```bash
# 测试所有包
go test -v ./...

# 测试单个包
go test -v ./crypto/...

# 测试单个文件（包内所有测试）
go test -v ./server/ -run TestCertmagic

# lint（跳过 _test.go 文件）
make lint   # 等价: go tool golangci-lint run --timeout 10m --verbose
```

## 构建标签 (Build Tags)

- `headless`：用于 headless/Android 构建，编译 `cmd/easyss/start_headless.go` 而非 `start.go`+`tray.go`
- 注意 `cmd/easyss/start.go` 和 `tray.go` 头部有 `//go:build !headless`
- 系统代理（`sysproxy*.go`）不是托盘专属：三条启动路径共用 `App.setupSysProxy`/`teardownSysProxy`（`main.go`），headless 在核心启动成功后同样设置系统代理、退出信号到达时撤销，`disable_sys_proxy` 是统一开关（设置失败只记警告，因为 root/systemd 下 gsettings 与用户会话总线常常不可达）

## 配置相关

- 默认配置文件名为 `config.json`，位于二进制同目录
- v2 配置自动迁移到 v3：`client/config/migrate.go` 中的 `MigrateV2Config()` 处理转换
- v3 客户端配置入口：`client/config/config.go` 中的 `ClientConfig` 结构体
- v3 服务端配置入口：`server/config/config.go` 中的 `FileConfig`/`ServerConfig`。服务端配置的加载与归一化统一走 `config.LoadConfig`（读文件 → 版本校验 `SupportedConfigVersion` → `applyDefaults` → `ResolveFilePaths`），`cmd/easyss-server` 不再自己排列这些步骤；`applyDefaults` 只收编没有其他 owner 的配置策略（`timeout` 写回、`log.level` 取 `sharedconfig.DefaultLogLevel`），`server.allowed_methods`（`GetAllowedMethods`）、`transport.h2_*`（`buildHTTPServer`）与 `shaper.*`（`shaper.Config.Normalize`）的空值/0 值语义仍由各自消费点负责，以免出现第二份默认值
- `-show-config-example` 的完整示例由 `server/config.ExampleConfig()` 提供（与 `FileConfig` 定义相邻，默认值全部引用 sharedconfig 常量，必填项用占位符），测试固定"示例本身已归一化"
- **DERP 私有化依赖两个 fork**：`tailscale.com` 与 `github.com/tailscale/tailcat` 通过 `go.mod` 的 `replace` 指向同级目录的 `easyss/derp-dialer` 分支（`../tailscale`、`../tailcat`），它们提供 `derphttp.SetDialer`（region 客户端也生效）、`magicsock.Options.DERPDialer`、`wgengine.Config.DERPDialer` 与 `tailcat.{Server,Client}.{DERPDialer,DERPOnly}`。本机验证用相对路径；CI/发布必须换成 GitHub 上的 fork 版本（`replace tailscale.com => github.com/nange/tailscale <版本>`），上游合并后再删除 replace
- `timeout` 是全部派生超时（TCP/UDP 空闲、拨号、DNS 响应、连接轮换、服务端 h2 连接空闲）的唯一旋钮，取值范围 **[15, 60]** 秒：非正值取默认值 30，越界取最近的边界；归一化统一由 `config.NormalizeTimeout`/`config.TimeoutDuration` 负责（客户端 `applyDefaults`/`TimeoutDuration`、简单模式覆盖 `ApplySimpleOverrides`、服务端 `server/config.applyDefaults`（由 `LoadConfig` 调用）与 `server.Start` 都必须经过它，不要各自判断）
- `tun_mtu`（完整模式 `local.tun_mtu`，简单模式同名 `tun_mtu`，默认 1500，钳制到 **[1280, 9000]**）是 TUN 设备 MTU 与 tun2socks netstack MTU 的**唯一**来源，归一化统一由 `config.NormalizeTunMTU` 负责（客户端 `applyDefaults`/`TunMTU()`、简单模式覆盖、`tun.New`、提权 helper 都必须经过它）。设备那一侧统一由各平台的**创建脚本**写入，MTU 是它们的第 9 个位置参数：linux `ip link set dev ... mtu`、darwin `ifconfig ... mtu`、Windows `netsh interface ipv4/ipv6 set subinterface ... mtu=`（wintun 适配器的 MTU 无法由 tun2socks 设置，wireguard-go 只把它记在内存里）；darwin/linux 的直连路径上 tun2socks 也会按同一个值设置一次（幂等），而脚本是 fd 路径唯一能改设备 MTU 的地方，keep-alive 重跑脚本时也会把它修回。`Manager.engineMTU` 在 fd 路径上以设备真实 MTU 为准兜底（超出配置区间时封顶到上限），`warnOnMTUMismatch` 在创建脚本之后核对设备与 netstack 的 MTU：netstack 的 MTU 小于设备 MTU 时会静默丢弃设备交上来的超限包（UDP、ICMP 与 IP 分片），而 TCP 因 MSS 由 netstack 通告而不受影响
- 显示完整配置示例：`./easyss -show-config-example`
- `vpn.*` 是节点组网的配置面（见关键架构要点 15 与 `docs/vpn-design.md`）：`vpn.enabled=false`（默认）时全链路零影响；`relay_only` 缺省为 **true**（TUN 下必须为 true，冲突时启动阶段强制并告警、运行期拒绝启用 TUN）；`peer_port`/`overlay_cidr`/`derp_addr` 都由**访问器**派生而不是写回结构体（`applyDefaults` 没有错误返回值，也早于 `--local-port` 覆盖），严格校验集中在 `vpnnode.NewConfig(Options)`，常量与归一化在 `config/vpn.go`；`peers[].address` 与发布的 `<exe>/vpn/peer.txt` **必须是完整展开格式**（短格式会去拉官方 DERPMap，违反零外部依赖），`vpnnode.AssertFullAddr` 在配置校验与发布前各拦一次；所有 peer 内嵌的 DERP 主机必须与本节点一致（DERP 私有化只支持单一 S，`vpnnode.assertPeersShareDERP`）；`overlay_cidr` 的前缀长度被钳在 `[/16, /30]`（槽位表按段容量分配，`/8` 及更大会申请 MiB~GiB 级内存）；状态目录 `<exe>/vpn/`（`node-identity.json`、`client.key`、`peer.txt`）三份文件都是 0600、目录 0700，client key 必须跨重启稳定（`allow_clients` 的前提）

## 关键架构要点

1. **传输层**：基于 Go 1.26 标准库 HTTP/2（不依赖 `golang.org/x/net/http2`），初始 1 个 `http.Transport`（`MaxConnsPerHost=1`），按需懒加载扩容（活跃流达到 `stream_threshold` 阈值且仍小于 `conn_count_max` 上限时新建连接），通过 least-active 策略调度；TLS 握手使用 uTLS Chrome 指纹伪装；服务端和客户端 HTTP/2 参数（帧大小、窗口大小、HEADER TABLE SIZE）分别配置以增强伪装效果
2. **应用帧协议**：HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER），`cipher_len:3 + ciphertext` 作为 CryptoRecord 边界；`protocol.ReadFrame/WriteFrame` 处理帧级别的编解码
3. **两阶段加密**：① Bootstrap 阶段：AES-256-GCM 加密初始握手帧（含目标地址和方法协商）；② Session 阶段：协商后的 AEAD（AES-256-GCM 或 ChaCha20-Poly1305），HKDF+salt 派生 C2S/S2C 方向独立密钥，每方向独立计数器 nonce
4. **回落对抗**：服务端首个 CryptoRecord 解密/验证失败时，回落成正常 HTML 首页（伪装为普通网站）；一旦发送 octet-stream 响应头则只能 close/RST stream。fallback 由 `handler.NewFallback(FallbackConfig)` 构造出 `*Fallback` 实例，在 `server.Start()` 中一次性注入 `ProxyHandler`/`ProbeHandler` 与 `/` 路由：模式配置与部署身份在构造后只读，实例级缓存有界，因此不存在包级可变状态，也没有"必须在使用前调用"的隐式顺序契约（未注入的零值 handler 回落到包级内置实例）。伪装强度分两层：
   - **部署级身份**（`fallback_random.go`）：每次构造用 `crypto/rand` 种子派生一套稳定身份——主题 CSS 的 `{{token}}` 由同一色相族派生、并逐项按相对亮度夹紧对比度，站点名/导航/页脚/`Last-Modified` 同样每实例随机。同一实例内所有客户端看到完全相同的页面（真实静态站的行为，也是生成页缓存的前提），不同实例之间彼此不同。
   - **HTTP 真实性层**（`fallback_http.go`）：自动生成模式下补齐 `Content-Length`/`Last-Modified`/`ETag`/`Accept-Ranges`，条件请求返回 304；浏览器式内容请求（`Accept` 含 `text/html`）命中未知路径时返回 404。目录/自定义/反代三种 fallback 模式不受这两层影响，状态码与行为保持原样。
5. **端点**：`POST /v3/tcp`、`POST /v3/udp`、`POST /v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）；`GET /v3/probe` 返回启动时预生成的随机数据（需 `x-es` 携带 master key 派生的能力令牌），供客户端主动探测 slot 连接的真实下载速度
6. **服务端**：需要 sudo 运行（443 端口 + ICMP）；TLS 证书通过 certmagic 自动管理（Let's Encrypt ACME）或手动指定证书文件
7. **SSRF 防护与 DNS pinning**：服务端在握手阶段解析 HANDSHAKE 中的 target **一次**，任一地址落在 LAN/私有/保留网段即用 400 拒绝，并把这次解析的结果随会话传给拨号路径；拨号只拨这些已校验的字面 IP，不把域名交给 `net.Dialer`，因此 SSRF 检查与实际连接用的是同一次解析，没有可供 DNS-rebinding 翻转答案的第二次解析。next proxy 路径仍把域名交给上游代理解析（被墙/仅代理侧可解析的域名依赖它），属明确接受的可信组件残余风险
8. **流量整形**：`shaper` 包将帧分批打包为 CryptoRecord，填充至固定大小档位（128/512/1500 字节），支持按预算比例注入 cover traffic（随机 COVER 帧），批处理窗口默认 3ms
9. **双向中继**：`relay.Bidirectional` 在 client↔server 间拷贝数据，共享空闲计时器，连接关闭时回调 exactly once；支持 stall 检测和流量统计
10. **统计与监控**：`stats` 包维护全局原子计数器（streams、bytes、RTT、DNS 缓存命中/未命中、fallback 页面等）；通过 HTTP 代理端口的 `/stats` 端点暴露 JSON 快照；`StreamMeter` 提供 per-stream 吞吐量监控
11. **NextProxy 动态学习**：`server/nextproxy` 从 DNS 响应中自动提取 CNAME 目标域名和解析 IP，动态加入代理列表，无需预配置完整域名
12. **v2→v3 配置迁移**：`client/config/migrate.go` 自动检测 v2 格式配置文件并通过 `MigrateV2Config()` 转换为 v3 格式，迁移后备份原文件为 `.bak`
13. **开机网络未就绪时的启动韧性**：`runner.Run` 里服务端域名预解析（`resolveServerDomain`，有界单次尝试）失败**不再是致命错误**——开机自启动时 WiFi 常常还没初始化完，此时进程照常启动并监听本地端口，解析失败降级为启动警告（`runner.ErrServerDomainUnresolved`，托盘给出"网络尚未就绪、已在后台重试"提示）。预解析的三层超时集中在 `client/dns/timeouts.go`：单次往返 `dnsQueryTimeout`、每个 DNS 条目 `dns.ResolveItemTimeout`（条目的 A/AAAA 并发共享它，保证黑洞服务器不会独吞预算）、一次完整预解析 `dns.PreResolveTimeout`（runner/client.New/TUN helper 三条路径共用，并预留一个条目预算给系统 DNS 兜底，见 `dns.WithSystemDNSFallbackReserve`）。后台 `retryServerDomain` 按指数退避（1s→15s，带 ±20% 抖动）持续重试直到成功或 `Core.Stop`；每次尝试前调用 `dns.ResetResolveState()` 清掉内置 DNS 熔断（3 分钟冷却）与系统 DNS 发现缓存（空结果缓存 5 分钟），否则"网络已恢复"会被这两处状态拖后数分钟。成功后关闭 `Core.ServerDomainReady()` 通道，同时把预解析到的地址交给客户端（`Core.publishServerIPs` → `client.Client.SetServerIPs`）：传输层拨服务端域名时优先拨这些字面 IP（客户端侧 DNS pinning，TLS 的 SNI/证书校验仍用原域名），单次尝试有界，失败时只把**本次**拨号回退给操作系统解析器、**不丢弃**预解析结果（一次失败可能只是瞬态——网络切换、接口绑定过期、服务端短暂抖动；丢掉它会让进程此后只能依赖系统解析器，而 pinning 存在的意义正是系统 DNS 不可靠时仍能连上。服务端真的换了 IP 时，每次拨号先花一次有界尝试再走域名回退），因此系统 DNS 坏掉/被污染（例如家用路由器返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答，见 `dns.normalizeEDNS0Answer`）也能连上。TUN 的启用以该通道为前提（`canStartTunNow`）：未就绪时不启动 TUN（避免把系统 DNS 指向本机转发服务器后陷入解析递归，或缺默认网关导致脚本失败），启动路径与托盘点击都给出提示，网络恢复后由用户手动开启；`client.RefreshServerIPV6` 在启用 TUN 前补齐降级启动期间为空的服务器 IPv6，保证 TUN 脚本安装 IPv6 默认路由。所有依赖与调参在派发 goroutine 之前捕获（`serverDomainRetry`），避免与测试替换包级变量产生数据竞争
14. **配置快照与运行期状态分离**：`App.cfg` 是 `atomic.Pointer[ClientConfig]` 指向的**不可变快照**——菜单改动一律走 `App.updateConfig`（克隆 → 改 → CAS 交换），启动/切换用 `App.adoptConfig` 整体换装并只把快照交给新会话，因此不存在"菜单原地写、切换 Clone 或运行中核心读"的数据竞争。运行期会变的状态不放进配置：TUN 是否生效由 `client.Client.SetTunMode` 显式告知（`tunMode atomic.Bool`，直连拨号路径 `dialAddr`/`dialerRefreshLoop` 读它），配置里的 `local.enable_tun2socks` 只是"下次启动的偏好"（`mobile` 没有托盘开关路径，故 `client.New` 用该字段播种 `tunMode`，`App.Start` 在决定本会话是否真的启用 TUN 后再覆盖一次）
15. **节点组网（VPN）**：`vpn`/`vpn/node` 两个包提供"节点之间互相访问对端自身服务端口"的能力，DERP 中继由 easyss 服务端内嵌（`vpn.NewDERPServer` 挂 `/derp`，经 `vpn.NewDERPMount` 与 fallback 页面共存），不依赖 Tailscale 官方 relay/control plane。分界线是**是否引用 `tailcat`**：服务端只需要 `vpn`（+2.6 MiB），任何对 tailcat 的引用都会把 WireGuard 引擎与 gVisor netstack 拖进二进制（+10 MiB），`vpn/deps_test.go` 用 `go list -deps` 钉住它。拓扑是"每个访问侧为每个对端跑一个 tailcat Client，对端跑 tailcat Server"（tailcat 客户端不接受入站，Server 没有 netstack 拨号 API），对端身份与虚拟 IP 都由 tailcat 公钥确定性派生，因此零控制面、零 IP 分配。要点：① 对端面复用 `client/proxy.Socks5Server`（`router.NewDirectOnly()` + `DisableDNSIntercept` + `LoopbackDialContext`），内层 CONNECT 目标恒为字面 `127.0.0.1:<port>`，对端只可能拨自己的 loopback，不可能成为内网跳板；② 访问侧不新增监听端口，而是 `Socks5Options.VPN`（`client/proxy.VPNRoute` 接口，**定义在消费方**避免导入环）注入现有 SOCKS5 路由，TUN 模式下 tun2socks 的单一出口天然走同一条路径；③ `vpn.enabled=false`（默认）时 `VPN==nil`，既有路径逐字节不变；④ `relay_only`（默认 true）经 **tailcat 的 `DERPOnly` 选项**（`vpnnode` 的 `PeerFaceOptions`/`ClientSetOptions` 透传）落到 tailscale 的进程级调试开关 `TS_DEBUG_ALWAYS_USE_DERP`：tailcat 在 `createEngine` 里、**创建 WireGuard 引擎之前**写它（magicsock 建 socket 时读取），因此 TUN 冲突只能在 `startVPN` 里强制、运行期只能拒绝（`Core.CheckVPNTunCompat`）；⑤ **内嵌 DERP 是私有端点**：它只接待来自**本机回环**的请求（`vpn.NewDERPMount` 按 `RemoteAddr` 判定，其余来源一律得到伪装页面，公网上没有任何"回答 DERP 协议"的路径），节点侧则由 `runner.newDERPDialer` 交给 tailcat 一个拨号器（`DERPDialer` 选项），把 tailcat 到 DERP 的每条 TCP 连接经 `StreamHandler.OpenTCPStream` 送进 easyss 隧道（`net.Pipe` 适配，复用生产路径上的中继；拨号上下文要 `context.WithoutCancel`——DERP 客户端在拨号返回后立刻取消它，而流的寿命是整个 DERP 连接）；服务端在握手阶段认出"目标就是我自己的 `derp_addr`"后改拨 `127.0.0.1:<listen>`（`server/handler` 的 `localDERP`/`dialTarget`，该特例跳过后面的 SSRF 判定，因此只能由**完全匹配**触发）。**必须用拨号器而不是 `ALL_PROXY`**：tailcat 在 `createEngine` 里调用 `netns.SetEnabled(false)`，netns 的 SOCKS 包装根本不生效。代价是**只支持单一 S**：所有节点必须通告同一个 DERP `host:port`，`vpnnode.assertPeersShareDERP` 在启动时拒绝不一致的 peer 地址。TUN 因此不再需要为 DERP 主机装绕行路由（`vpnnode.Bypass`、`Config.BypassIPs` 与创建脚本的第 10/11 个位置参数已删除）；⑥ 对端名字由 DNS 静态钩子就地应答（A → overlay IPv4，AAAA → NOERROR 空应答，其余原样转发），语义收敛在 `dns.StaticReply`，但**必须接在两个前端上**：TUN 写进系统解析器的是**公网** DNS（`tunDNS`/`PreferredSystemDNS`），其查询经 tun2socks 以 53 端口到达 `client/proxy` 的 DNS 拦截器（`vpnStaticNames` 把它当作 `VPNRoute` 的可选能力），而 `client/dns` 的转发服务器只服务 `enable_forward_dns` 的 LAN 部署

## 版本信息注入

Makefile 通过 `-ldflags` 向 `version/` 包注入以下变量，其余变量由 `runtime/debug.ReadBuildInfo()` 和 `runtime` 在 `init()` 中自动填充：

- `version.Name` → `"Easyss"`
- `version.GitTag` → `git describe --tags`
- `version.BuildDate` → 构建时间
- `version.GitCommit` → 完整 commit hash
- `version.GitTreeState` → `"clean"` 或 `"dirty"`
- `version.Platform` → `runtime.GOOS`/`runtime.GOARCH`
- `version.GoVersion` → `runtime.Version()`

## Windows 构建注意事项

- 客户端使用纯 Go 系统托盘库 `github.com/gogpu/systray`（零 CGO，Windows 走 Win32、Linux 走 D-Bus SNI、macOS 走 goffi FFI）；服务端禁用 CGO。go.mod 通过 `replace` 指向 `github.com/nange/systray v0.3.0-easyss.1` 分支（import 路径不变），该分支修复了上游 issue #39——菜单打开期间 `SetMenu` 重建会把点击派发到别的菜单项；因此运行时重建菜单树（如 UWP 豁免列表）是安全的
- 客户端产物连 `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`

## 其他注意事项

- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录
- 在用户没有明确要求提交代码前，都不提交代码
- 提交代码前，先执行`make lint`，检查代码风格，存在问题则需要先修复再提交代码
- 当用户要求提交PR时，需要在单独的分支提交代码并推送，PR标题采用英文，PR描述使用中文
