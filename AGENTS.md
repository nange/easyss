# AGENTS.md — Easyss v3

## 项目概述

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，客户端+服务端架构。

## Go 环境

- 模块路径：`github.com/nange/easyss/v3`（根模块原地升级，不维护 v2/v3 双模块）
- Go 版本：`1.27.2+`（go.mod）

## 核心目录结构

```
rule/               规则文件解析与匹配（IP/CIDR/域名/glob/regexp），客户端路由与服务端链式代理共用
cmd/easyss/         客户端入口，含系统托盘(systray) UI（nange/systray 分支，纯 Go 零 CGO）
cmd/easyss-server/  服务端入口，单文件 main.go
client/             客户端核心：Client 结构体
client/config/      客户端配置（JSON 解析、简化模式/旧版配置转换）
client/router/      GeoIP + 域名列表路由引擎
client/dns/         DNS 转发服务器 + freecache 双缓存
client/proxy/       SOCKS5/HTTP 代理服务器 + StreamHandler
client/tun/         TUN2socks 虚拟网卡 + ICMP 代理
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
- 系统代理（`sysproxy*.go`）不是托盘专属：三条启动路径共用 `App.setupSysProxy`/`teardownSysProxy`（`main.go`），实际是否应用由 `App.sysProxyApplied` 记录；`App.Stop`/`App.Close` 是两个退出入口，都按“撤销系统代理 → 拆 TUN → 停核心”执行——`Stop` 只撤销本进程应用过的代理，`Close` 供托盘退出/切换无条件清理上一次运行或异步开关留下的系统代理。headless 在核心启动成功后设置系统代理、退出时由 `App.Stop` 撤销，`disable_sys_proxy` 是统一开关（设置失败只记警告，因为 root/systemd 下 gsettings 与用户会话总线常常不可达）

## 配置相关

- 默认配置文件名为 `config.json`，位于二进制同目录
- 简化模式/旧版配置在 `LoadConfig` 中通过 `BuildSimpleConfig` 转换为 v3 完整配置：**只发生在内存里，不回写配置文件，也不生成 `.bak`**。`MigrateV2Config`/`MigrateV2ToV3` 已删除；完整模式的 JSON 解析统一走 `ParseConfigJSON`（`LoadConfig` 也调用它）
- v3 客户端配置入口：`client/config/config.go` 中的 `ClientConfig` 结构体
- **配置线格式与运行时类型是同一份**：`shaper.Config`（`Cover` 匿名嵌入使 `cover_budget_*` 平铺）与 `log.Config` 同时是客户端/服务端的 JSON 形状，两个 `config` 包直接复用，`log.Init(Config)` 是日志配置的唯一应用入口；不要再定义同形的 `ShaperConfig`/`LogConfig`。`Cover.IdleTimeout`/`MinSize`/`MaxSize` 是伪装层固定属性，保持 `json:"-"`
- 配置字段命名：服务端 `server.host`（ACME 标识符：域名或公网 IPv4）、`server.port`（默认 443，监听所有网卡）与可选的 `server.bind`；客户端完整模式 `servers[].host`。旧键 `server.domain` / `server.listen` / `servers[].address` 由各自的 `UnmarshalJSON` 兼容映射（`listen` 拆成 `bind`+`port`），新旧键同时出现会报错；配置版本仍为 3。`ServerConfig.ListenAddr()` 是监听地址的唯一格式化入口，且对 `Port == 0` 回退到默认 443；服务端 `server.host` 的"不含端口"约束在 `validateTLS` 的取证模式判定**之前**统一校验（手工证书模式同样适用）。客户端在 `LoadConfig`/`ParseConfigJSON`/`BuildSimpleConfig` 以及命令行覆盖（`ApplySimpleOverrides`）之后统一由 `validateServers` 拒绝空 `host` 或带端口的 `host`，地址拼装（`ServerURL`/`DefaultServerAddr`/`ServerListAddrs`）统一走 `net.JoinHostPort`，IPv6 字面量自动加方括号
- v3 服务端配置入口：`server/config/config.go` 中的 `FileConfig`/`ServerConfig`。服务端配置的加载与归一化统一走 `config.LoadConfig`（读文件 → 版本校验 `SupportedConfigVersion` → `applyDefaults` → `FileConfig.Validate`（`validateAllowedMethods`/`validateTransport`/`validateTLS`/`validateListenOrDefault`）→ `ResolveFilePaths`），`cmd/easyss-server` 不再自己排列这些步骤；`applyDefaults` 收编没有其他 owner 的配置策略（`timeout` 写回、`log.level` 取 `sharedconfig.DefaultLogLevel`、`server.port` 取 `sharedconfig.DefaultServerPort`，以及 `transport.h2_max_frame_size`/`h2_recv_buf_*` 的 0 值写回），`server.allowed_methods` 的未知值在 `validateAllowedMethods` 直接报错（空列表仍由 `GetAllowedMethods` 回落到默认对），`h2_*` 的越界值在 `validateTransport` 按标准库实际接受区间拒绝（`server.New` 也会调用 `FileConfig.Validate`，绕过 `LoadConfig` 的测试/嵌入式调用同样被拒）；`buildHTTPServer` 只读归一化后的值（仅保留 `effectiveH2` 的 0 值兜底，供绕过 LoadConfig 的调用方使用），每条连接的并发流上限固定为 `HTTP2ServerMaxConcurrentStreams`=128，不可配，`shaper.*` 仍由 `shaper.Config.Normalize` 负责，以免出现第二份默认值；`transport.protocols` 已删除（它从不驱动 `buildHTTPServer`，实际协议集合恒为 h2 + 供 fallback 使用的 h1），老配置里的该键由 `json.Unmarshal` 忽略
- **"证书从哪来"只有一个判定入口**：`server/config/tls.go` 的 `UsesManualCertificate`（手工证书 vs ACME，`initTLS` 与启动日志都读它，不再各自判断 `cert_path`/`key_path` 是否非空）、`ACMESubjectIsIP`（标识符是不是 IP 字面量，决定是否显式请求 `shortlived` profile 与打哪一行启动日志）与 `validateTLS`（配置加载阶段的校验：证书文件必须成对、ACME 模式下 `host` 必填、IP 只接受**公网 IPv4 字面量**）。`validateTLS` 的公网性判据是 `util.IsLANIP`，**故意比 certmagic 的 `SubjectQualifiesForPublicCert` 更严**（后者不含 CGNAT/TEST-NET/240/4 等段，只靠 CA 侧兜底），不要为"对齐"放宽；IPv6 与 IPv4-mapped 字面量被拒绝是因为客户端与服务端地址都是 `IP:port` 形态（见关键架构要点 6）
- `-show-config-example` 的完整示例由 `server/config.ExampleConfig()` 提供（与 `FileConfig` 定义相邻，默认值全部引用 sharedconfig 常量，必填项用占位符），测试固定"示例本身已归一化"
- `timeout` 是全部派生超时（TCP/UDP 空闲、拨号、DNS 响应、连接轮换、服务端 h2 连接空闲）的唯一旋钮，取值范围 **[15, 60]** 秒：非正值取默认值 30，越界取最近的边界；归一化统一由 `config.NormalizeTimeout`/`config.TimeoutDuration` 负责（客户端 `applyDefaults`/`TimeoutDuration`、简单模式覆盖 `ApplySimpleOverrides`、服务端 `server/config.applyDefaults`（由 `LoadConfig` 调用）与 `server.Start` 都必须经过它，不要各自判断）
- **派生超时只在一个地方填充零值**：`config.Timeouts`（`Base`/`Dial`/`StreamIdle`/`UDPIdle`/`DNSResp`/`ConnLifetime`）由 `config.NewTimeouts` 派生，`Timeouts.Normalize` 负责把**零值字段**按 `Base` 补齐（只填零值，不钳制显式给出的 `Base`）。每个公开构造器入口（`proxy.NewSocks5Server`/`NewHTTPProxyServer`/`NewStreamHandler`、`handler.NewProxyHandler` 及其三个子 handler、`http2.New`、`nextproxy.New`）调用 `Normalize` 一次，其余地方直接读字段，**不要再写 `if x <= 0 { x = DefaultX }`**。`config.Default{StreamIdle,UDPIdle,Dial,ConnLifetime}Timeout` 这四个变量已删除（它们曾与散布在 17 处构造器里的二次默认值并存）；需要默认值时用 `config.NewTimeouts(0)`。**两个入口必须拿到同一份 `Timeouts`**：HTTP 入口曾经只接收基础超时再自行派生，导致同一个直连目标在 SOCKS5 入口按 `base/3`（默认 10s）超时、在 HTTP 入口按 `base`（默认 30s）超时
- 仍保留零值判断的两处是**语义**而非默认值，不要一并收敛：`NewProxyHandler` 的 `HandshakeTimeout <= 0`（"0 表示沿用 `Timeouts.Base`"的覆盖字段）与 `udpPool.receiveLoop` 的 `respTimeout <= 0`（"0 表示关闭读空闲"的功能开关）
- `http_port` 未配置（0）时由 `socks_port` 推导（`config.DefaultHTTPPortOffset`，即 `+1000`）：**简单模式与完整模式语义一致**，推导只有 `client/config.normalizeHTTPPort` 一处实现（`applyDefaults` 与 `ApplySimpleOverrides` 都调用它），`socks_port` 为 0（不启动本地代理）时不推导；显式配置的 `http_port` 优先，而 `socks_port=0` + `http_port>0` 仍是启动错误（`runner.ErrSocksRequired`）
- **本地代理端点地址只有一个来源**：`util.LocalProxyListenAddr(bindAll, port)` 给监听，`util.LocalProxyDialAddr(bindAll, port)` 给本机消费方（HTTP 入口反向代理、TUN 引擎与提权 helper、系统代理与会话环境、托盘 `/stats` 取值），`util.Socks5URI` 只是后者的 `socks5://` 包装；`bind_all` 时两者分别是 `[::]` 与同族回环 `[::1]`。任何消费方都不得再自己拼 `127.0.0.1:<port>`：监听可能只接受 IPv6 回环（不支持 IPv4-mapped 的平台），而系统代理/会话环境指向一个连不上的入口等于断网。`setSysProxy`/`proxyEnvState.set` 因此接收完整地址而不是端口，地址统一由 `sysProxyAddr(cfg)` 从配置推导
- `tun_mtu`（完整模式 `local.tun_mtu`，简单模式同名 `tun_mtu`，默认 1500，钳制到 **[1280, 9000]**）是 TUN 设备 MTU 与 tun2socks netstack MTU 的**唯一**来源，归一化统一由 `config.NormalizeTunMTU` 负责（客户端 `applyDefaults`/`TunMTU()`、简单模式覆盖、`tun.New`、提权 helper 都必须经过它）。设备那一侧统一由各平台的**创建脚本**写入，MTU 是它们的第 9 个位置参数：linux `ip link set dev ... mtu`、darwin `ifconfig ... mtu`、Windows `netsh interface ipv4/ipv6 set subinterface ... mtu=`（wintun 适配器的 MTU 无法由 tun2socks 设置，wireguard-go 只把它记在内存里）；darwin/linux 的直连路径上 tun2socks 也会按同一个值设置一次（幂等），而脚本是 fd 路径唯一能改设备 MTU 的地方，keep-alive 重跑脚本时也会把它修回。`Manager.engineMTU` 在 fd 路径上以设备真实 MTU 为准兜底（超出配置区间时封顶到上限），`warnOnMTUMismatch` 在创建脚本之后核对设备与 netstack 的 MTU：netstack 的 MTU 小于设备 MTU 时会静默丢弃设备交上来的超限包（UDP、ICMP 与 IP 分片），而 TCP 因 MSS 由 netstack 通告而不受影响
- 显示完整配置示例：`./easyss -show-config-example`

## 关键架构要点

1. **传输层**：基于 Go 1.26 标准库 HTTP/2（不依赖 `golang.org/x/net/http2`），初始 1 个 `http.Transport`（`MaxConnsPerHost=1`），按需懒加载扩容（活跃流达到 `stream_threshold` 阈值且仍小于 `conn_count_max` 上限时新建连接），通过 least-active 策略调度；TLS 握手使用 uTLS Chrome 指纹伪装；服务端和客户端 HTTP/2 参数（帧大小、窗口大小、HEADER TABLE SIZE）分别配置以增强伪装效果。**「判死即换连接」由换代保证**：判死只关得掉底层 `net.Conn`，而 net/http 的池没有关闭承载活跃流的连接的 API，那条 h2 `ClientConn` 何时被移出池取决于 stdlib 内部清理的调度时机，因此 `transportSlot.invalidateConn` 在关闭连接的同时把槽位换到新一代（`advanceGeneration`），下一次 `Open` 只能拨号；`CloseIdleConnections` 的异步收敛不再是这条保证的一部分（#226），池一律通过 `transportSlot.transport()` 读取。**「代 == 连接」是连接身份的唯一来源**：池与它拨出的那条连接打包成 `slotTransport{tr, conn}`；一"代"最多只有一条连接，连接一关（`trackedConn.Close`，即 net/http 回收）就整代作废（`retireGeneration` 把槽位换到新一代）。因此流在提交请求时记下的那一代（`http2Stream.gen`）就是它实际用过的那条连接——判死（`InvalidateConn` → `invalidateConn`）与判活（`ConnAlive`）都只在自己那一代里进行，写路径上不需要再"快照"一次；判死换池之后另一条流拨出的新连接，一条正在死去的流永远碰不到（#226、#229 之后仍然存在的"把新连接记成自己的身份、误杀健康连接"的窗口因此结构上不存在）。唯一例外是 net/http 会为达到服务端 `maxConcurrentStreams` 的连接在同一张池里再拨一条：`MaxConnsPerHost=1` 挡不住（它计的是 net/http 自己的 persistConn，而这条路径会主动让出计数去再拨 TCP），旧的 h2 连接也不会被关闭；该上限**固定为 128、不开放配置**（客户端用这个值判断连接是否已满，调小会让例外更早出现；它同时是 SETTINGS 里的可被动特征），配合调度器按 least-active 摊流，要上千条同时打开的流才会撞上，实际不可达。`HTTP2Config.StrictMaxConcurrentRequests` 在当前标准库实现里会卡死（排队者握着预约、等待者握着 reqHeaderMu），不能用——详见 `slotTransport` 的注释与 `config.HTTP2ServerMaxConcurrentStreams`
2. **应用帧协议**：HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER），`cipher_len:3 + ciphertext` 作为 CryptoRecord 边界；`protocol.ReadFrame/WriteFrame` 处理帧级别的编解码
3. **两阶段加密**：① Bootstrap 阶段：AES-256-GCM 加密初始握手帧（含目标地址和方法协商）；② Session 阶段：协商后的 AEAD（AES-256-GCM 或 ChaCha20-Poly1305），HKDF+salt 派生 C2S/S2C 方向独立密钥，每方向独立计数器 nonce
4. **回落对抗**：服务端首个 CryptoRecord 解密/验证失败时，回落成正常 HTML 首页（伪装为普通网站）；一旦发送 octet-stream 响应头则只能 close/RST stream。fallback 由 `handler.NewFallback(FallbackConfig)` 构造出 `*Fallback` 实例，在 `server.Start()` 中一次性注入 `ProxyHandler`/`ProbeHandler` 与 `/` 路由：模式配置与部署身份在构造后只读，实例级缓存有界，因此不存在包级可变状态，也没有"必须在使用前调用"的隐式顺序契约（未注入的零值 handler 回落到包级内置实例）。伪装强度分两层：
   - **部署级身份**（`fallback_random.go`）：每次构造用 `crypto/rand` 种子派生一套稳定身份——主题 CSS 的 `{{token}}` 由同一色相族派生、并逐项按相对亮度夹紧对比度，站点名/导航/页脚/`Last-Modified` 同样每实例随机。同一实例内所有客户端看到完全相同的页面（真实静态站的行为，也是生成页缓存的前提），不同实例之间彼此不同。
   - **HTTP 真实性层**（`fallback_http.go`）：自动生成模式下补齐 `Content-Length`/`Last-Modified`/`ETag`/`Accept-Ranges`，条件请求返回 304；浏览器式内容请求（`Accept` 含 `text/html`）命中未知路径时返回 404。目录/自定义/反代三种 fallback 模式不受这两层影响，状态码与行为保持原样。
5. **端点**：`POST /v3/tcp`、`POST /v3/udp`、`POST /v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）；`GET /v3/probe` 返回启动时预生成的随机数据（需 `x-es` 携带 master key 派生的能力令牌），供客户端主动探测 slot 连接的真实下载速度
6. **服务端**：需要 sudo 运行（443 端口 + ICMP）；TLS 证书通过 certmagic 自动管理（Let's Encrypt ACME）或手动指定证书文件。**ACME 的标识符既可以是域名，也可以是公网 IPv4 字面量**（`server.host`，IP-only 模式）：Let's Encrypt 的 IP 地址证书（RFC 8738，2026-01 GA）**必须是短生命周期证书**（约 160 小时、无 CN），因此 `manageCert` 对 IP 标识符显式请求 `shortlived` profile（常量 `acmeProfileShortLived`；LE 对 `ip` 标识符会自动选它，显式请求是为了不让"必须是短生命周期"依赖服务端自动选择，profile 名不再被 CA 承认时 acmez 会报 `unknown profile name`）；它**只能用 tls-alpn-01 验证**（dns-01 被 RFC 8738 禁止，而 `acmeCfg.DisableHTTPChallenge` 早已为 true），所以公网 443 在首次签发与每次续期时都必须可达（续期由 `certmagic.NewCache` 起的后台维护 goroutine 负责，约每 4.5 天一次）。客户端侧无需改动：`servers[].host` 是 IP 时既有的 IP 分支会跳过预解析/pinning，uTLS 对 IP 字面量不发 SNI、按 IP SAN + 系统根证书校验；但**客户端 `sn` 必须留空**（它才是校验用的名字，填了别的域名会校验失败——那正是"Cloudflare 优选 IP"那套配置，与 IP 证书模式正好相反）
7. **SSRF 防护与 DNS pinning**：服务端在握手阶段解析 HANDSHAKE 中的 target **一次**，任一地址落在 LAN/私有/保留网段即用 400 拒绝，并把这次解析的结果随会话传给拨号路径；拨号只拨这些已校验的字面 IP，不把域名交给 `net.Dialer`，因此 SSRF 检查与实际连接用的是同一次解析，没有可供 DNS-rebinding 翻转答案的第二次解析。next proxy 路径仍把域名交给上游代理解析（被墙/仅代理侧可解析的域名依赖它），属明确接受的可信组件残余风险
8. **流量整形**：`shaper` 包将帧分批打包为 CryptoRecord，填充至固定大小档位（128/512/1500 字节），支持按预算比例注入 cover traffic（随机 COVER 帧），批处理窗口默认 3ms
9. **双向中继**：`relay.Bidirectional` 在 client↔server 间拷贝数据，共享空闲计时器，连接关闭时回调 exactly once；支持 stall 检测和流量统计
10. **统计与监控**：`stats` 包维护全局原子计数器（streams、bytes、RTT、DNS 缓存命中/未命中、fallback 页面等）；通过 HTTP 代理端口的 `/stats` 端点暴露 JSON 快照（与 `/tun` 共用回环守卫，`bind_all` 时也不出网）；快照按语义分段嵌入而 JSON 保持平铺，计数器由 `stats.counters`/`stats.derivedCounters` 表统一驱动 Reset/Collect，漏登记会被 `stats` 包的测试拦住；`StreamMeter` 提供 per-stream 吞吐量监控
11. **NextProxy 动态学习**：`server/nextproxy` 从 DNS 响应中自动提取 CNAME 目标域名和解析 IP，动态加入代理列表，无需预配置完整域名
12. **简化模式/旧版配置转换**：`LoadConfig` 自动识别简化模式（含旧版 v2 键）并在内存中通过 `BuildSimpleConfig` 转换为 v3；不回写配置文件，也不生成 `.bak`。完整模式的 JSON 解析统一走 `ParseConfigJSON`
13. **开机网络未就绪时的启动韧性**：`runner.Run` 里服务端域名预解析（`resolveServerDomain`，有界单次尝试）失败**不再是致命错误**——开机自启动时 WiFi 常常还没初始化完，此时进程照常启动并监听本地端口，解析失败降级为启动警告（`runner.ErrServerDomainUnresolved`，托盘给出"网络尚未就绪、已在后台重试"提示）。预解析的三层超时集中在 `client/dns/timeouts.go`：单次往返 `dnsQueryTimeout`、每个 DNS 条目 `dns.ResolveItemTimeout`（条目的 A/AAAA 并发共享它，保证黑洞服务器不会独吞预算）、一次完整预解析 `dns.PreResolveTimeout`（runner/client.New/TUN helper 三条路径共用，并预留一个条目预算给系统 DNS 兜底，见 `dns.WithSystemDNSFallbackReserve`）。后台 `retryServerDomain` 按指数退避（1s→15s，带 ±20% 抖动）持续重试直到成功或 `Core.Stop`；每次尝试前调用 `dns.ResetResolveState()` 清掉内置 DNS 熔断（3 分钟冷却）与系统 DNS 发现缓存（空结果缓存 5 分钟），否则"网络已恢复"会被这两处状态拖后数分钟。成功后关闭 `Core.ServerDomainReady()` 通道，同时把预解析到的地址交给客户端（`Core.publishServerIPs` → `client.Client.SetServerIPs`）：传输层拨服务端域名时优先拨这些字面 IP（客户端侧 DNS pinning，TLS 的 SNI/证书校验仍用原域名），单次尝试有界，失败时只把**本次**拨号回退给操作系统解析器、**不丢弃**预解析结果（一次失败可能只是瞬态——网络切换、接口绑定过期、服务端短暂抖动；丢掉它会让进程此后只能依赖系统解析器，而 pinning 存在的意义正是系统 DNS 不可靠时仍能连上。服务端真的换了 IP 时，每次拨号先花一次有界尝试再走域名回退），因此系统 DNS 坏掉/被污染（例如家用路由器返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答，见 `dns.NormalizeEDNS0Answer`）也能连上。TUN 的启用以该通道为前提（`canStartTunNow`）：未就绪时不启动 TUN（避免把系统 DNS 指向本机转发服务器后陷入解析递归，或缺默认网关导致脚本失败），启动路径与托盘点击都给出提示，网络恢复后由用户手动开启；`client.RefreshServerIPV6` 在启用 TUN 前补齐降级启动期间为空的服务器 IPv6，保证 TUN 脚本安装 IPv6 默认路由。所有依赖与调参在派发 goroutine 之前捕获（`serverDomainRetry`），避免与测试替换包级变量产生数据竞争
14. **配置快照与运行期状态分离**：`App.cfg` 是 `atomic.Pointer[ClientConfig]` 指向的**不可变快照**——菜单改动一律走 `App.updateConfig`（克隆 → 改 → CAS 交换），启动/切换用 `App.adoptConfig` 整体换装并只把快照交给新会话，因此不存在"菜单原地写、切换 Clone 或运行中核心读"的数据竞争。运行期会变的状态不放进配置：TUN 是否生效由 `client.Client.SetTunMode` 显式告知（`tunMode atomic.Bool`，直连拨号路径 `dialAddr`/`dialerRefreshLoop` 读它），配置里的 `local.enable_tun2socks` 只是"下次启动的偏好"（`mobile` 没有托盘开关路径，故 `client.New` 用该字段播种 `tunMode`，`App.Start` 在决定本会话是否真的启用 TUN 后再覆盖一次）。服务器切换的事务体在 `App.restartServiceInSequence`，托盘只通过 `appUI` 提供“系统代理是否勾选/TUN 菜单勾选”两个状态；`session.run` 仍负责把整套“停→起/回滚”串行化
15. **挂起复核：时钟离差只产生嫌疑，判死必须由一次真实往返给出**：系统睡眠/VM 暂停会静默丢掉底层连接（NAT 表项过期，两端都还认为它活着），而 net/http 的空闲回收（`closeIfIdle` 在 `len(streams)>0` 时直接返回）与 `tooIdleLocked`（依赖只在 `streams==0` 时写入的 `lastIdle`）都只作用于**没有活跃流**的连接，因此承载常驻流（push/mtalk/DERP）的槽位会一直把这条死连接当作可用——第一个新流必然踩上去，白等引导 4s + 判活 2s 才由判死路径换连接，并把同连接的在飞流一起切断。识别手段是**墙钟推进减单调钟推进**，因为 Go 的单调时钟在挂起期间冻结（darwin 即 `mach_absolute_time`）——**用 ticker 的实到间隔测不到挂起**，定时器在自己的时间轴上并没有迟到。实现上有三条不可动摇的设计：①`suspendSampler` 只存**一个标量**（`suspendOffset` = 墙钟 UnixNano 减进程内单调读数，醒着时恒定、挂起一次跳过睡眠时长），存两个读数会在并发采样时撕裂成负离差（假阴性），而这个差值天然是一次不可分割的采样；②**健康循环与开流路径共享同一个采样器**（`slotLifecycle.suspend`，通过 `observeSuspend` 采样），CAS 既推进基线又认领这次观测，于是"一次挂起恰好一个观测者"是结构性保证——两份独立基线会让迟到的那一份把已经复核过、标记已清掉的槽位重新武装并重复记账；开流路径上的采样不可省略：实测待机回来第一个开流发生在醒来后 **0.0s（中位数）**，几乎必然早于第一个健康周期，只靠定时器那条流仍会盲踩死连接；③健康循环的吞吐采样基线重置走事件号（`suspendEvents`/`resetSamplingOnSuspend`），因为"是谁先发现的挂起"与"基线归属哪个 goroutine"无关，`lastHeavy` 始终只由健康循环写。阈值（`SuspendDivergenceThreshold`）只把承载连接的活跃槽位标记为 `reverify`，**绝不关闭连接**；判死权在开流路径上：`http2Transport.reverifySlot` 用一次 `HEAD /v3/probe`（`SuspendReverifyTimeout`）复核，活着就原样复用（假阳性只花一个 RTT），不通才按身份 CAS 失效换连接，无法判定（未配置探测令牌）时保守放行。另有三条纪律：①判活跑在剥掉调用方取消的上下文上（否则"本地连接刚关掉"就会判健康连接死刑）；②失效只针对复核开始时观测到的那一代（`transportSlot.invalidateConn`，与 `http2Stream.InvalidateConn` 共用同一代身份，任何"复核慢一步杀掉新连接"的窗口都不允许存在）；③启发式判据本身有假阳性（NTP/手动调时间向前跳、VM 快照恢复、`CLOCK_BOOTTIME`/`mach_continuous_time` 这类含睡眠的单调钟），因此它只能产生嫌疑。逐流的连带失败（net/http 的 `errClientConnForceClosed`，"force closed via ClientConn.Close"）在 `client/proxy.isTransientStreamError` 里归为瞬时错误记 Debug：它按构造只由本进程的判死产生，连接级事件已由上面的 Info 锚点覆盖

16. **规则解析与匹配只有一份实现**：`rule` 包是"规则文件 → 匹配集合"的唯一入口，`client/router` 的自定义 `direct_file`/`proxy_file` 与 `server/nextproxy` 的 `next_proxy_file` 都用它。`rule.Set` 同时持有 IP/CIDR/域名/glob/regexp 四类条目并自带锁（`MatchHost`/`MatchHostKind`/`HasDomain`/`AddIP`/`AddDomain`），因此：① router 的 `customDirect`/`customProxy` 各只是一个 `*rule.Set`，此前 direct/proxy 两半是八个字段加四对逐行重复的匹配函数（dupl 报了 4 处），现在结构上不存在第二份；② 归一化只有三个函数：匹配侧 `rule.NormalizeHost`（去端口、去 FQDN 尾点、小写）与 `rule.canonicalIP`（IPv4-mapped 折叠为 IPv4），解析侧 `rule.normalizeDomainKey`（规则条目不可能带端口，省掉端口探测；30 万行内置列表上那两次字符串扫描是可见的启动成本）——前两者是"同一个主机在匹配时收敛成同一形态"的唯一入口，后者只用于把规则文件里的一行变成 map 键——DNS 缓存以小写为键、qname 带尾点、拨号目标是 `host:port`，三者在匹配前必须收敛成同一种形态，这是"`WWW.Example.COM.` 命中缓存却路由到不同分支"那类问题的根因；③ glob 与 `regexp:` 一律按 `(?i)` 编译，与 DNS 名本身大小写不敏感的语义对齐（内置列表实际含 8 条 `regexp:`、554 条 `full:`、其余为裸域名；`(?i)` 的代价落在噪声范围内，但**不是零**——`MatchHostRule` 实测约 +15%（机器相关，区间 12%~19%），主要来自 `NormalizeHost` 的归一化，换掉了此前大小写敏感的错误语义）；④ 解析错误**不再静默**：`rule.ParseFile` 返回带行号的 `*rule.Error` 列表，由调用方决定致命性——客户端只记启动告警（`Router.CustomFileError`，内置规则仍生效），服务端 `next_proxy_file` 直接启动失败（缺项意味着本该走代理的域名悄悄直连出网）；⑤ `rule.DomainSet`（`full:`/`regexp:`/裸域名，`Match(domain, withSub)`）承担内置 geosite 列表，`client/router.GeoSite` 只是它的类型别名。**行尾注释不支持**：`#` 在正则/glob 里可能合法，README 的示例因此把注释单独成行

17. **DNS 路由按查询域名决定，而不是按解析器地址**：服务端 UDP 会话的目标是解析器（如 `8.8.8.8:53`），但"这条查询该直连还是走下一级代理"只有 QNAME 知道。因此目标是 53 端口的会话**推迟拨号**（`udpHandler.Handle` 里 `dnsSession=true` 时不拨，出站连接由主循环在处理第一条查询时建立）；UDP 的 DNS 部分集中在 `server/handler/udp_dns.go`（路由类型与实现、会话的 DNS 状态 `dnsState`、路由判定与重绑、应答学习），`udp.go` 只保留数据报中继本身，两者的接口只有 `isDNSPort`、`observeDNSFrame`、`dialRoute` 三处，路由判定复用 next proxy 的文件规则（`udpRouteDialer.routeForDomain` → `NextProxy.ShouldProxy`），`enable_udp=false` 时命中的域名也退回直连（UDP 无法承载）。同一条会话里路由可能变化——客户端把**同一个 socket 上的所有查询复用到同一条隧道流**（交换键是「客户端数据报来源地址 + 上游」，与域名无关，见 `client/proxy.udpPool.acquireExchange`），因此一条服务端 UDP 会话可能先后承载两个域名，而客户端的规则里没有服务端的 `next_proxy_file`，无从预判命中与否；此时 `rebindRoute` **先按新路由拨号，成功后才安装新连接并关闭旧连接**（拨号失败保留旧连接与旧路由，同一帧只拨一次；`conn` 与 `connRoute` 在 `installUpstream` 的同一个临界区里一起替换，由 `closeUpstream` 一起清空），并为新连接**补一个读取 goroutine**——连接作为参数传入（`startUpstreamReader(conn)` / `readFromTarget(conn)`），不依赖 goroutine 启动后再从会话取，因此"一条连接一个 reader"是结构性保证；新旧 reader 允许短暂并存，各自只读参数里的那条连接；`readers.WaitGroup` 的 `Add` 与 `Wait` 都只发生在主 goroutine 上；读取结果带回产生它的连接，主循环在结束会话前再核对来源，因此旧连接在快照之后才报出的错误不会误杀新连接；重绑失败后进入 `rebindCooldown`（10s），窗口内命中同一路由的查询直接复用旧连接、不再同步拨号，重绑期间在飞的查询由客户端自己重试。`[UDP_DNS]` 的 `via_next_proxy` 因此是这条查询**实际**使用的出站路径（日志在重绑之后输出、读的是当前连接的路由；重绑失败时另带 `route_changed=true` 与 `route_pending=true`）；客户端拦截到的 **DNS over TCP** 无需单独处理：它经隧道送达服务端时就是一个 UDP 数据报（`client/proxy` 的 TCP DNS 会话复用代理 UDP 交换，见 `tcpDNSSession.resolveProxy`），走的就是这条按域名路由的路径；ICMP 不受影响（原始 socket 无法由 SOCKS5 承载）

18. **DNS 拦截：判定与执行各一份，投递模型两份**：`client/proxy` 的 DNS 拦截分三层，边界是刻意划的。①**判定**：`dnsInterceptor.plan`（`dns.go`）把一条查询解析成 `dnsPlan`（Block / 缓存命中 / 直连 / 代理），UDP 与 TCP 共用；②**执行**：`dns_exec.go` 是"动作 → 结果"的唯一实现——`executeSync` 处理三条同步分支（Block / 缓存命中 / 直连），`prepareProxied` 负责钳制 EDNS0 并封包，`finishProxied` 是代理应答的**唯一**后处理入口（规范化畸形 EDNS0 → 按 ipv6 策略剥离 AAAA → 写代理缓存 → 记录结果 → 按自定义域名学习），`postProcessProxied` 只是它的字节流包装（UDP 前端拿到的是原始数据报，改动后必须重新 Pack）；③**投递模型**：UDP 异步（应答由 `udpPool.receiveLoop` 在任意时刻送回，前端提供 `onData`），TCP 同步（一条连接顺序使用自己的交换，`waitResponse` 阻塞等待）。**投递模型不许合并**：把 UDP 改成阻塞等待会丢掉多应答/重传语义，把 TCP 改成回调也没有收益。此前"执行"是两份（`dns_udp.go` 逐行实现、`tcpDNSSession.resolve` 再抄一遍），已经在规范化与重新封包上漂移——`dns_exec_test.go` 用"同一条查询经两条前端路径产生完全相同的缓存条目"守住这条一致性
19. **DNS 熔断判定只有一处**：`client/dns/builtin.go` 的 `BuiltinRouteFor(hasFailover func() bool) BuiltinRoute`，返回三个互斥状态（`BuiltinRouteFirst` / `BuiltinRouteSkip` / `BuiltinRouteRetry`）。**必须是三态而不是两个布尔**：用 `try`/`armOnFailure` 两个布尔时，"熔断中但没有兜底"与"健康"在调用方看起来一样，于是"无视冷却重试"那段分支永远不可达、对应的 Warn 也永远不打印。`hasFailover` 也必须是**惰性函数值而不是 bool**：判定只有在熔断已置位时才需要知道"有没有兜底"，提前求值会让健康路径为每次预解析付一次系统 DNS 发现（darwin 的 `networksetup` 约 48ms，`TestCachePrePopulateDoesNotProbeSystemDNSWhenBuiltinWorks` 守着这条约束）。三条调用路径共享判定但**各自保留循环**——`QueryWithBuiltinFirst`（并发竞争取首个成功）、`Cache.PrePopulateWithFallback`（串行 + 每条目预算 + 系统兜底预留）、`client.resolveServerIPV6`（逐条目预算）——三者的调度与预算模型本来就不同，合并循环会破坏各自的超时语义。唯一的规则是：**只有存在系统 DNS 兜底时才熔断内置池**（无兜底时熔断会把 3 分钟冷却变成彻底中断，Android 上系统 DNS 对应用不可见正是这种情形）；反过来，熔断已置位但当前没有兜底时**无视冷却**，仍试内置池

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
- `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`
- **平台脚本的唯一落盘入口是 `client/tun.WriteScriptToTemp`**（内部 `normalizeScriptEOL`）：本包的 TUN 创建/关闭脚本与 `cmd/easyss` 提权 helper（`tun_helper_linux.go`/`tun_helper_darwin.go`）的脚本都必须走它，`.bat` 会被统一成 CRLF，`.sh` 原样。cmd.exe 按 OEM 代码页逐行读取批处理文件，LF 行尾在中文 Windows（OEM 代码页 936）上会让多字节注释与换行错位、注释被当成命令执行（实测 create 脚本一条配置命令都发不出去），而 `go:embed` 取的是工作区字节——Raw 单文件下载、编辑器存成 LF、第三方镜像都不经过 `.gitattributes` 的 eol 转换。`.sh` 绝不能转成 CRLF（bash 会报 `\r: command not found`）；`scripts_test.go` 另有一条断言守仓库的 CRLF 约定
- **平台脚本的位置参数只有一个构造点：`client/tun.ScriptArgs`**（`script_args.go`）。三套布局并不相同——windows 的第 4 位是掩码、第 8 位是适配器 DNS，linux/darwin 的第 4 位是本地网关、第 8 位是本地网关 v6；darwin 的第 5 位必须是**裸** IPv6 地址（脚本自己补 `/64`），linux 的第 2 位必须是"地址/掩码"。地址拼接（`ipSub`）、IPv6 去前缀（`bareV6Addr`）与 MTU 归一化都收在里面，调用方只填 `DeviceConfig`/DNS/MTU，再用 `Create()`/`Close()`（或 `CreateFor`/`CloseFor` 指定平台）渲染。生产代码（`Manager.createTunDevAndSetIPRoute`/`closeTunDevAndDelIPRoute`、helper 的 `runCreateScript`/`runCloseScript`）与测试**共用**它，不允许再手写位置参数切片：这些字面量过去散在 12 处，抄错只会在运行时由脚本的 "failed near" 暴露。helper 侧的唯一转换点是 `tun_helper_unix.go` 的 `scriptArgsFor`（`proxy.TunConfig` → `tun.ScriptArgs`），它必须带上 `TunMask`，否则 fd 路径会把地址装成 `/32`、直连路径装成 `/16`（两条路径都能上网，偏差不会报错），见 `TestHelperAndDirectPathsShareTheScriptArgs`
- **TUN 拆除只有一条路径：`Manager.teardown(reason, owner)`**（`client/tun/teardown.go`）。`Owner` 显式声明"路由与系统 DNS 归谁回收"（`OwnerLocal` = 直连路径与本进程安装的一切；`OwnerHelper` = 提权 helper 的 fd 路径，主进程只停自己的引擎并关 fd），`TeardownReason` 只决定日志与错误呈现口径、**不决定做哪些步骤**；它的四个值都由 `Start`/`Stop` 真实产生（`stop`、`start-failed`、`start-cancelled`、`create-failed`）——`create-failed` 专指创建脚本失败（脚本先装地址后装路由，是唯一"必然有东西要删"的失败），由 `Start` 的 `createFailed` 标记算出，`TestCreateScriptFailureUsesItsOwnReason` 钉住它不会被退回成死枚举。是否真的执行某一步由本次会话实际做成了什么决定（`engineUp`/`deviceUp`/`dnsTouched`），`tornDown` 保证一次会话只拆一次。Start 的失败/取消路径与 `Stop()` 都收敛到这里；它们取代了 `fdMode`/`SkipRouteCleanup`/`helperSignalled` 三套互相独立又必须永远同步的隐式条件（`SkipRouteCleanup` 字段已删除，`Owner` 由 `ownerForConfig` 从 `Config.DeviceFD > 0` 唯一推导）。`session.tunOwner` 记录本次会话的所有权并传给 `verifyTeardown`，`tunDown` 的"等 helper 退出"只对 `OwnerHelper` 生效。teardown 不自己加锁：`Stop` 持有 `stopMu`，而 Start 路径绝不能拿它——`Stop` 正持有 `stopMu` 等 `<-done`，`done` 由 Start 的 defer 关闭，那样会死锁。**有两步不属于 teardown**：①engine 启动失败时由 `Start` 自己调 `engine.Stop` 释放它可能已打开的设备（此时 `engineUp` 尚未置位，teardown 不会做；tun2socks 的 `engine.Start` 先打开设备再建协议栈，失败路径不清理，见 #550/#552）；②fd 路径上的裸 fd 由 `Start` 在**能证明它还没进引擎**的两处早退点关闭（`releaseUnownedFD`：进 `engine.Start` 之前的取消失败，与 `validateEngineKey` 拒绝配置）。一旦进入 `engine.Start`，fd 归属就交给上游（`parseDevice` 可能已把它包装成设备），失败由 `engine.Stop` 兜底，本进程不再插手——按 fd 号猜"这是不是我的设备"是不可靠的：两个独立 socket 的 `ino`/`dev` 都是 0，同一字符设备的两次打开 `dev/ino/rdev/mode` 完全相同，任何身份核对都会在号码复用时误关别人的 fd。为了让"引擎失败"必然发生在 fd 已交出之后，`validateEngineKey`（`engine_key.go`）会在 `engine.Insert` 之前把 `engine.Start` 在 `parseDevice` 之前必然拒绝的配置先拒掉——即 `LogLevel`（`log.ParseLevel`）、小于 1s 的 `UDPTimeout`、以及 `Socks5Addr`（复刻上游 `parseProxy` 的 `url.Parse` + `proxy.Parse`；`Key.Interface` 与 `Key.RestAPI` 在本项目恒为空，故只有这三项）。校验只读入参、无副作用
- **`Manager` 的会话状态在 `New` 里就建好，`Start` 只认领它**：`Start` 由调用方派发的 goroutine 执行（`session.startTunEngine`），从启用路径返回到那个 goroutine 真正进入 `Start` 之间有一个调度窗口，托盘的下一次点击可以在窗口内到达 `Stop`。若 `ctx`/`cancel` 只在 `Start` 里创建，`Stop` 在那个窗口只会看到"从未启动"并直接返回，而 `Start` 随后照常把引擎、路由与 DNS 全部建立起来——session 那边已经把 manager 收走并发布了 `EnableTun2socks=false`：界面说关了、流量还在隧道里，而且再没有人持有它去停（下一次点击会新建一套，engine 的包级默认设备被覆盖，前一套再也停不掉）。因此 `Stop` 无条件落下 `cancel()`，只在 `started` 时等 `done`（两者在 `mu` 下一起快照），并且同一个 manager 只允许 `Start` 一次。回归测试见 `TestManagerStopBeforeStartGoroutineRuns` 与 `TestFaultStopRacesWithStart`


## 其他注意事项

- 日志约定：服务端每条 TCP/ICMP 流只保留入口 `[SERVER] proxy` 一条 Info 与结束时的 `logHandlerResult` 一条结果日志；UDP 会话的连接/路由变化事件（`[UDP] upstream connected`、`[UDP_DNS]`）仍按原级别保留，因为一条会话可能重绑多次。客户端流内生命周期用 Debug，失败由入口（SOCKS5/HTTP）记录一次。handler 内部不要为拨号/连接/失败再打 Info/Error；需要区分失败阶段时用错误包装（`fmt.Errorf("...: %w", err)`）或 `streamResult` 携带
- 测试注入约定：**不新增包级可变函数钩子**（`var x = func...`），一律用构造器参数、结构体字段或接口注入；测试只改自己构造的实例（`client.sysDeps`、`tun.platform`、`handler.outboundDeps`、`runner.options`、`appDeps`、`tunOps`、`proxyEnvState`、`dns.systemServers` 等）。生产默认值由构造器或 `defaultXxx()` 填入，**零值不回落**：新增依赖字段后忘了填是编译期就能看见的 nil 调用，而不是悄悄走生产实现。唯一例外是 `client.sysDeps` 的 nil 字段——它的 `dialBound` 默认值必须引用所属 `Client`，没法在结构体字面量里填。`t.Parallel` 已按包启用；仍需串行的只有共享进程级状态的测试（fd 号、全局 logger、`scripts.*`、`t.Setenv`、真实端口），它们在文件顶部或测试函数上注明原因
- 注释约定：代码注释只写"读代码看不出来、写错会静默出错"的两类事实——顺序/锁/生命周期约束，以及外部系统行为或跨包契约。不写代码演进史（"过去…现在…"、"取代了某某"），不写枚举式清单（"只有这五个方法会写这个字段"）——这类表述一旦过时就成了错误文档；设计取舍与历史写在 commit message 或本文件。单个注释块不超过 3 行，函数名已经说清楚的不要再加 godoc
- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录
- 在用户没有明确要求提交代码前，都不提交代码
- 提交代码前，先执行`make lint`，检查代码风格，存在问题则需要先修复再提交代码
- 当用户要求提交PR时，需要在单独的分支提交代码并推送，PR标题采用英文，PR描述使用中文
