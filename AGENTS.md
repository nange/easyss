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
- v3 服务端配置入口：`server/config/config.go` 中的 `FileConfig`/`ServerConfig`。服务端配置的加载与归一化统一走 `config.LoadConfig`（读文件 → 版本校验 `SupportedConfigVersion` → `applyDefaults` → `validateTLS` → `ResolveFilePaths`），`cmd/easyss-server` 不再自己排列这些步骤；`applyDefaults` 只收编没有其他 owner 的配置策略（`timeout` 写回、`log.level` 取 `sharedconfig.DefaultLogLevel`），`server.allowed_methods`（`GetAllowedMethods`）、`transport.h2_*`（`buildHTTPServer`）与 `shaper.*`（`shaper.Config.Normalize`）的空值/0 值语义仍由各自消费点负责，以免出现第二份默认值
- **"证书从哪来"只有一个判定入口**：`server/config/tls.go` 的 `UsesManualCertificate`（手工证书 vs ACME，`initTLS` 与启动日志都读它，不再各自判断 `cert_path`/`key_path` 是否非空）、`ACMESubjectIsIP`（标识符是不是 IP 字面量，决定是否显式请求 `shortlived` profile 与打哪一行启动日志）与 `validateTLS`（配置加载阶段的校验：证书文件必须成对、ACME 模式下 `domain` 必填、IP 只接受**公网 IPv4 字面量**）。`validateTLS` 的公网性判据是 `util.IsLANIP`，**故意比 certmagic 的 `SubjectQualifiesForPublicCert` 更严**（后者不含 CGNAT/TEST-NET/240/4 等段，只靠 CA 侧兜底），不要为"对齐"放宽；IPv6 与 IPv4-mapped 字面量被拒绝是因为客户端与服务端地址都是 `IP:port` 形态（见关键架构要点 6）
- `-show-config-example` 的完整示例由 `server/config.ExampleConfig()` 提供（与 `FileConfig` 定义相邻，默认值全部引用 sharedconfig 常量，必填项用占位符），测试固定"示例本身已归一化"
- **DERP 私有化依赖两个 fork**：`tailscale.com` 与 `github.com/tailscale/tailcat` 通过 `go.mod` 的 `replace` 指向同级目录的 `easyss/derp-dialer` 分支（`../tailscale`、`../tailcat`），它们提供 `derphttp.SetDialer`（region 客户端也生效）、`magicsock.Options.DERPDialer`、`wgengine.Config.DERPDialer` 与 `tailcat.{Server,Client}.{DERPDialer,DERPOnly}`。本机验证用相对路径；CI/发布必须换成 GitHub 上的 fork 版本（`replace tailscale.com => github.com/nange/tailscale <版本>`），上游合并后再删除 replace
- `timeout` 是全部派生超时（TCP/UDP 空闲、拨号、DNS 响应、连接轮换、服务端 h2 连接空闲）的唯一旋钮，取值范围 **[15, 60]** 秒：非正值取默认值 30，越界取最近的边界；归一化统一由 `config.NormalizeTimeout`/`config.TimeoutDuration` 负责（客户端 `applyDefaults`/`TimeoutDuration`、简单模式覆盖 `ApplySimpleOverrides`、服务端 `server/config.applyDefaults`（由 `LoadConfig` 调用）与 `server.Start` 都必须经过它，不要各自判断）
- `tun_mtu`（完整模式 `local.tun_mtu`，简单模式同名 `tun_mtu`，默认 1500，钳制到 **[1280, 9000]**）是 TUN 设备 MTU 与 tun2socks netstack MTU 的**唯一**来源，归一化统一由 `config.NormalizeTunMTU` 负责（客户端 `applyDefaults`/`TunMTU()`、简单模式覆盖、`tun.New`、提权 helper 都必须经过它）。设备那一侧统一由各平台的**创建脚本**写入，MTU 是它们的第 9 个位置参数：linux `ip link set dev ... mtu`、darwin `ifconfig ... mtu`、Windows `netsh interface ipv4/ipv6 set subinterface ... mtu=`（wintun 适配器的 MTU 无法由 tun2socks 设置，wireguard-go 只把它记在内存里）；darwin/linux 的直连路径上 tun2socks 也会按同一个值设置一次（幂等），而脚本是 fd 路径唯一能改设备 MTU 的地方，keep-alive 重跑脚本时也会把它修回。`Manager.engineMTU` 在 fd 路径上以设备真实 MTU 为准兜底（超出配置区间时封顶到上限），`warnOnMTUMismatch` 在创建脚本之后核对设备与 netstack 的 MTU：netstack 的 MTU 小于设备 MTU 时会静默丢弃设备交上来的超限包（UDP、ICMP 与 IP 分片），而 TCP 因 MSS 由 netstack 通告而不受影响
- 显示完整配置示例：`./easyss -show-config-example`
- `./easyss vpn` 是节点组网的 CLI 面（在 flag 解析之前分派，见 `cmd/easyss/vpn_cmd.go`）：`identity [--json]` 打印 client nodekey 与节点地址（原 `-show-vpn-identity`，已移除），`regen [--node] [--client] [--dry-run] [--json]` 重新生成身份，不带开关时两个都换。**地址是 `(身份, 中继集合)` 的纯函数、不落盘**，所以"配置变了"只需重新读一次；`regen` 换的是身份本身，旧身份先备份成 `<file>.bak`（固定名，**每次重新生成都覆盖它**，因此每个身份文件最多只留一份备份 = 上一次生效的身份）。`runner.RegenerateVPNIdentity` 的顺序是**先生成 → 再推导 → 最后才写**：推导不出地址（要换身份时）必须在任何文件被改写之前失败，否则本节点会丢掉唯一有效地址而运维什么也没得到；`--dry-run` 与真写共用同一份新密钥字节，因此它预览的就是将要落盘的东西。`vpn.LoadOrCreate` 仍然"绝不静默覆盖"，坏文件只提示该跑 `easyss vpn regen`；`vpn.RegenerateFile` 是唯一被允许覆盖身份文件的入口，且先备份后写入，备份本身也是原子覆盖（`writeFileAtomic`：截断重写会同时失去新旧两份凭据）。`vpn.IdentityRegenPending(path)` 用**内容比较**（不是 mtime）判断"当前身份与备份不同"，供 `vpn identity` 打一行"手上地址还是旧的"提示；mtime 判据在同一次操作先后写入、以及拷回备份回滚之后都不可靠。
- `easyss vpn` 的**终端文案是中文**（与 `vpnUsage`、顶层 `-h` 一致），但配置字段名（`vpn.peers[].address`/`vpn.allow_clients`）、命令名与 flag 名保持原文：运维要拿它们去配置文件里搜索或复制命令，翻译过的字段名搜不到。`vpn` 包内其余字符串（错误、日志）仍是英文——它们面向排障与日志检索，且已被测试与文档引用；`vpn.PeerUpdateHint`/`vpn.ConsequenceHint`/`vpn.Recipient*` 是**显示文案**，因此是中文。
- `easyss vpn` 的**输出格式有契约**（`cmd/easyss/vpn_identity_test.go` 逐行固定，含空行）：身份值按"一次只讲一件事"分块、块间空一行（client nodekey / 中继列表 / 节点地址 / 附注 / 旧值），因为这些值全都要人**手动复制**到对端，挤在一起时容易把中继列表当成地址的一部分复制走。附注与"旧值"的文案按 **`VPNRegenResult.Replaced`（实际换掉的那一半）** 选，而不是调用方的 `Kinds`（请求换哪一半）：`vpn.PeerUpdateHint`/`vpn.ConsequenceHint`/`vpn.Recipient*` 都在 `vpn` 包（收件人字段与代价是身份的属性），只换 client key 时既不会回显逐字节没变的地址，也不会让人去改一个没变的字段；`--dry-run` 用同一份新密钥字节推导，因此它打印的就是将要落盘的那个身份。
- `vpn.*` 是节点组网的配置面（见关键架构要点 16）：`vpn.enabled=false`（默认）时全链路零影响；`relay_only` 缺省为 **true**（TUN 下必须为 true，冲突时启动阶段强制并告警、运行期拒绝启用 TUN）；`peer_port`/`overlay_cidr` 都由**访问器**派生而不是写回结构体（`applyDefaults` 没有错误返回值，也早于 `--local-port` 覆盖），严格校验集中在 `vpnnode.NewConfig(Options)`，常量与归一化在 `config/vpn.go`；**DERP 节点是一组而不是一台**：`servers[]` 里全部 `derp: true` 的条目共同构成同一 region 下的多个中继（`client/config.ClientConfig.DERPServers/VPNDERPAddrs`，`vpn.BuildRegion` 变参），没有任何标记时回退**当前连接的服务端**（不再固定 `servers[0]`）；两侧都**没有** `derp_addr` 配置项（端口转发/反代那种"对外 host:port 与监听不同"的形态明确不支持）：服务端由 `server.domain` + `server.listen` 端口推导（`FileConfig.ResolveDERPAddr`），客户端只能由 `derp` 标记派生，残留的旧键由 `LoadConfig` 打一条 `was removed and is ignored` 的 WARN 后忽略；**当前服务端必须在声明列表里**（`ClientConfig.ValidateDERPServer` → `runner.vpnOptions`，否则 `log.Error` + VPN 本会话缺席、代理照常），因为内嵌 DERP 只接待经本服务端隧道送达的连接；`peers[].address` 与发布的 `<exe>/vpn/peer.txt` **必须是完整展开格式**（短格式会去拉官方 DERPMap，违反零外部依赖），`vpnnode.AssertFullAddr` 在配置校验与发布前各拦一次；每个 peer 地址内嵌的 DERP 节点集合必须与本节点**相等**（`vpnnode.assertPeersShareDERPSet`，顺序无关、`config.CanonicalDERPAddr` 规范化后比较）；**地址令牌绝不进日志**（`runner.startVPN` 只打 `address_file`/`client_nodekey`/`derp_addrs`，全量地址只经 `easyss vpn identity` 与 `peer.txt` 交付）；`overlay_cidr` 的前缀长度被钳在 `[/16, /30]`（槽位表按段容量分配，`/8` 及更大会申请 MiB~GiB 级内存）；状态目录 `<exe>/vpn/`（`node-identity.json`、`client.key`、`peer.txt`）三份文件都是 0600、目录 0700，client key 必须跨重启稳定（`allow_clients` 的前提）

## 关键架构要点

1. **传输层**：基于 Go 1.26 标准库 HTTP/2（不依赖 `golang.org/x/net/http2`），初始 1 个 `http.Transport`（`MaxConnsPerHost=1`），按需懒加载扩容（活跃流达到 `stream_threshold` 阈值且仍小于 `conn_count_max` 上限时新建连接），通过 least-active 策略调度；TLS 握手使用 uTLS Chrome 指纹伪装；服务端和客户端 HTTP/2 参数（帧大小、窗口大小、HEADER TABLE SIZE）分别配置以增强伪装效果
2. **应用帧协议**：HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER），`cipher_len:3 + ciphertext` 作为 CryptoRecord 边界；`protocol.ReadFrame/WriteFrame` 处理帧级别的编解码
3. **两阶段加密**：① Bootstrap 阶段：AES-256-GCM 加密初始握手帧（含目标地址和方法协商）；② Session 阶段：协商后的 AEAD（AES-256-GCM 或 ChaCha20-Poly1305），HKDF+salt 派生 C2S/S2C 方向独立密钥，每方向独立计数器 nonce
4. **回落对抗**：服务端首个 CryptoRecord 解密/验证失败时，回落成正常 HTML 首页（伪装为普通网站）；一旦发送 octet-stream 响应头则只能 close/RST stream。fallback 由 `handler.NewFallback(FallbackConfig)` 构造出 `*Fallback` 实例，在 `server.Start()` 中一次性注入 `ProxyHandler`/`ProbeHandler` 与 `/` 路由：模式配置与部署身份在构造后只读，实例级缓存有界，因此不存在包级可变状态，也没有"必须在使用前调用"的隐式顺序契约（未注入的零值 handler 回落到包级内置实例）。伪装强度分两层：
   - **部署级身份**（`fallback_random.go`）：每次构造用 `crypto/rand` 种子派生一套稳定身份——主题 CSS 的 `{{token}}` 由同一色相族派生、并逐项按相对亮度夹紧对比度，站点名/导航/页脚/`Last-Modified` 同样每实例随机。同一实例内所有客户端看到完全相同的页面（真实静态站的行为，也是生成页缓存的前提），不同实例之间彼此不同。
   - **HTTP 真实性层**（`fallback_http.go`）：自动生成模式下补齐 `Content-Length`/`Last-Modified`/`ETag`/`Accept-Ranges`，条件请求返回 304；浏览器式内容请求（`Accept` 含 `text/html`）命中未知路径时返回 404。目录/自定义/反代三种 fallback 模式不受这两层影响，状态码与行为保持原样。
5. **端点**：`POST /v3/tcp`、`POST /v3/udp`、`POST /v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）；`GET /v3/probe` 返回启动时预生成的随机数据（需 `x-es` 携带 master key 派生的能力令牌），供客户端主动探测 slot 连接的真实下载速度
6. **服务端**：需要 sudo 运行（443 端口 + ICMP）；TLS 证书通过 certmagic 自动管理（Let's Encrypt ACME）或手动指定证书文件。**ACME 的标识符既可以是域名，也可以是公网 IPv4 字面量**（`server.domain`，IP-only 模式）：Let's Encrypt 的 IP 地址证书（RFC 8738，2026-01 GA）**必须是短生命周期证书**（约 160 小时、无 CN），因此 `manageCert` 对 IP 标识符显式请求 `shortlived` profile（常量 `acmeProfileShortLived`；LE 对 `ip` 标识符会自动选它，显式请求是为了不让"必须是短生命周期"依赖服务端自动选择，profile 名不再被 CA 承认时 acmez 会报 `unknown profile name`）；它**只能用 tls-alpn-01 验证**（dns-01 被 RFC 8738 禁止，而 `acmeCfg.DisableHTTPChallenge` 早已为 true），所以公网 443 在首次签发与每次续期时都必须可达（续期由 `certmagic.NewCache` 起的后台维护 goroutine 负责，约每 4.5 天一次）。客户端侧无需改动：`servers[].address` 是 IP 时既有的 IP 分支会跳过预解析/pinning，uTLS 对 IP 字面量不发 SNI、按 IP SAN + 系统根证书校验；但**客户端 `sn` 必须留空**（它才是校验用的名字，填了别的域名会校验失败——那正是"Cloudflare 优选 IP"那套配置，与 IP 证书模式正好相反）
7. **SSRF 防护与 DNS pinning**：服务端在握手阶段解析 HANDSHAKE 中的 target **一次**，任一地址落在 LAN/私有/保留网段即用 400 拒绝，并把这次解析的结果随会话传给拨号路径；拨号只拨这些已校验的字面 IP，不把域名交给 `net.Dialer`，因此 SSRF 检查与实际连接用的是同一次解析，没有可供 DNS-rebinding 翻转答案的第二次解析。next proxy 路径仍把域名交给上游代理解析（被墙/仅代理侧可解析的域名依赖它），属明确接受的可信组件残余风险
8. **流量整形**：`shaper` 包将帧分批打包为 CryptoRecord，填充至固定大小档位（128/512/1500 字节），支持按预算比例注入 cover traffic（随机 COVER 帧），批处理窗口默认 3ms
9. **双向中继**：`relay.Bidirectional` 在 client↔server 间拷贝数据，共享空闲计时器，连接关闭时回调 exactly once；支持 stall 检测和流量统计
10. **统计与监控**：`stats` 包维护全局原子计数器（streams、bytes、RTT、DNS 缓存命中/未命中、fallback 页面等）；通过 HTTP 代理端口的 `/stats` 端点暴露 JSON 快照；`StreamMeter` 提供 per-stream 吞吐量监控
11. **NextProxy 动态学习**：`server/nextproxy` 从 DNS 响应中自动提取 CNAME 目标域名和解析 IP，动态加入代理列表，无需预配置完整域名
12. **v2→v3 配置迁移**：`client/config/migrate.go` 自动检测 v2 格式配置文件并通过 `MigrateV2Config()` 转换为 v3 格式，迁移后备份原文件为 `.bak`
13. **开机网络未就绪时的启动韧性**：`runner.Run` 里服务端域名预解析（`resolveServerDomain`，有界单次尝试）失败**不再是致命错误**——开机自启动时 WiFi 常常还没初始化完，此时进程照常启动并监听本地端口，解析失败降级为启动警告（`runner.ErrServerDomainUnresolved`，托盘给出"网络尚未就绪、已在后台重试"提示）。预解析的三层超时集中在 `client/dns/timeouts.go`：单次往返 `dnsQueryTimeout`、每个 DNS 条目 `dns.ResolveItemTimeout`（条目的 A/AAAA 并发共享它，保证黑洞服务器不会独吞预算）、一次完整预解析 `dns.PreResolveTimeout`（runner/client.New/TUN helper 三条路径共用，并预留一个条目预算给系统 DNS 兜底，见 `dns.WithSystemDNSFallbackReserve`）。后台 `retryServerDomain` 按指数退避（1s→15s，带 ±20% 抖动）持续重试直到成功或 `Core.Stop`；每次尝试前调用 `dns.ResetResolveState()` 清掉内置 DNS 熔断（3 分钟冷却）与系统 DNS 发现缓存（空结果缓存 5 分钟），否则"网络已恢复"会被这两处状态拖后数分钟。成功后关闭 `Core.ServerDomainReady()` 通道，同时把预解析到的地址交给客户端（`Core.publishServerIPs` → `client.Client.SetServerIPs`）：传输层拨服务端域名时优先拨这些字面 IP（客户端侧 DNS pinning，TLS 的 SNI/证书校验仍用原域名），单次尝试有界，失败时只把**本次**拨号回退给操作系统解析器、**不丢弃**预解析结果（一次失败可能只是瞬态——网络切换、接口绑定过期、服务端短暂抖动；丢掉它会让进程此后只能依赖系统解析器，而 pinning 存在的意义正是系统 DNS 不可靠时仍能连上。服务端真的换了 IP 时，每次拨号先花一次有界尝试再走域名回退），因此系统 DNS 坏掉/被污染（例如家用路由器返回"OPT 在 ANSWER 段"的畸形 EDNS0 应答，见 `dns.normalizeEDNS0Answer`）也能连上。TUN 的启用以该通道为前提（`canStartTunNow`）：未就绪时不启动 TUN（避免把系统 DNS 指向本机转发服务器后陷入解析递归，或缺默认网关导致脚本失败），启动路径与托盘点击都给出提示，网络恢复后由用户手动开启；`client.RefreshServerIPV6` 在启用 TUN 前补齐降级启动期间为空的服务器 IPv6，保证 TUN 脚本安装 IPv6 默认路由。所有依赖与调参在派发 goroutine 之前捕获（`serverDomainRetry`），避免与测试替换包级变量产生数据竞争
14. **配置快照与运行期状态分离**：`App.cfg` 是 `atomic.Pointer[ClientConfig]` 指向的**不可变快照**——菜单改动一律走 `App.updateConfig`（克隆 → 改 → CAS 交换），启动/切换用 `App.adoptConfig` 整体换装并只把快照交给新会话，因此不存在"菜单原地写、切换 Clone 或运行中核心读"的数据竞争。运行期会变的状态不放进配置：TUN 是否生效由 `client.Client.SetTunMode` 显式告知（`tunMode atomic.Bool`，直连拨号路径 `dialAddr`/`dialerRefreshLoop` 读它），配置里的 `local.enable_tun2socks` 只是"下次启动的偏好"（`mobile` 没有托盘开关路径，故 `client.New` 用该字段播种 `tunMode`，`App.Start` 在决定本会话是否真的启用 TUN 后再覆盖一次）
15. **挂起复核：时钟离差只产生嫌疑，判死必须由一次真实往返给出**：系统睡眠/VM 暂停会静默丢掉底层连接（NAT 表项过期，两端都还认为它活着），而 net/http 的空闲回收（`closeIfIdle` 在 `len(streams)>0` 时直接返回）与 `tooIdleLocked`（依赖只在 `streams==0` 时写入的 `lastIdle`）都只作用于**没有活跃流**的连接，因此承载常驻流（push/mtalk/DERP）的槽位会一直把这条死连接当作可用——第一个新流必然踩上去，白等引导 4s + 判活 2s 才由判死路径换连接，并把同连接的在飞流一起切断。识别手段是**墙钟推进减单调钟推进**，因为 Go 的单调时钟在挂起期间冻结（darwin 即 `mach_absolute_time`）——**用 ticker 的实到间隔测不到挂起**，定时器在自己的时间轴上并没有迟到。实现上有三条不可动摇的设计：①`suspendSampler` 只存**一个标量**（`suspendOffset` = 墙钟 UnixNano 减进程内单调读数，醒着时恒定、挂起一次跳过睡眠时长），存两个读数会在并发采样时撕裂成负离差（假阴性），而这个差值天然是一次不可分割的采样；②**健康循环与开流路径共享同一个采样器**（`slotLifecycle.suspend`，通过 `observeSuspend` 采样），CAS 既推进基线又认领这次观测，于是"一次挂起恰好一个观测者"是结构性保证——两份独立基线会让迟到的那一份把已经复核过、标记已清掉的槽位重新武装并重复记账；开流路径上的采样不可省略：实测待机回来第一个开流发生在醒来后 **0.0s（中位数）**，几乎必然早于第一个健康周期，只靠定时器那条流仍会盲踩死连接；③健康循环的吞吐采样基线重置走事件号（`suspendEvents`/`resetSamplingOnSuspend`），因为"是谁先发现的挂起"与"基线归属哪个 goroutine"无关，`lastHeavy` 始终只由健康循环写。阈值（`SuspendDivergenceThreshold`）只把承载连接的活跃槽位标记为 `reverify`，**绝不关闭连接**；判死权在开流路径上：`http2Transport.reverifySlot` 用一次 `HEAD /v3/probe`（`SuspendReverifyTimeout`）复核，活着就原样复用（假阳性只花一个 RTT），不通才按身份 CAS 失效换连接，无法判定（未配置探测令牌）时保守放行。另有三条纪律：①判活跑在剥掉调用方取消的上下文上（否则"本地连接刚关掉"就会判健康连接死刑）；②失效只针对复核开始时观测到的那条连接（`transportSlot.invalidateConnFrom`，与 `http2Stream.InvalidateConn` 共用，任何"复核慢一步杀掉新连接"的窗口都不允许存在）；③启发式判据本身有假阳性（NTP/手动调时间向前跳、VM 快照恢复、`CLOCK_BOOTTIME`/`mach_continuous_time` 这类含睡眠的单调钟），因此它只能产生嫌疑。逐流的连带失败（net/http 的 `errClientConnForceClosed`，"force closed via ClientConn.Close"）在 `client/proxy.isTransientStreamError` 里归为瞬时错误记 Debug：它按构造只由本进程的判死产生，连接级事件已由上面的 Info 锚点覆盖
16. **节点组网（VPN）**：`vpn`/`vpn/node` 两个包提供"节点之间互相访问对端自身服务端口"的能力，DERP 中继由 easyss 服务端内嵌（`vpn.NewDERPServer` 挂 `/derp`，经 `vpn.NewDERPMount` 与 fallback 页面共存），不依赖 Tailscale 官方 relay/control plane。分界线是**是否引用 `tailcat`**：服务端只需要 `vpn`，任何对 tailcat 的引用都会把 WireGuard 引擎与 gVisor netstack 拖进二进制（+10 MiB），`vpn/deps_test.go` 用 `go list -deps` 钉住它。`vpn` 自己的体积也在涨：内嵌 DERP 中继（derpserver）+2.6 MiB，再加上 ⑥ 的 mesh 客户端（derphttp）后实测服务端二进制又 +1.0 MiB（darwin/arm64、`-s -w`：15.67 MiB → 16.68 MiB）——这是「多中继互联」的固定成本，仍远低于 tailcat。拓扑是"每个访问侧为每个对端跑一个 tailcat Client，对端跑 tailcat Server"（tailcat 客户端不接受入站，Server 没有 netstack 拨号 API），对端身份与虚拟 IP 都由 tailcat 公钥确定性派生，因此零控制面、零 IP 分配。要点：① 对端面复用 `client/proxy.Socks5Server`（`router.NewDirectOnly()` + `DisableDNSIntercept` + `LoopbackDialContext`），内层 CONNECT 目标恒为字面 `127.0.0.1:<port>`，对端只可能拨自己的 loopback，不可能成为内网跳板；② 访问侧不新增监听端口，而是 `Socks5Options.VPN`（`client/proxy.VPNRoute` 接口，**定义在消费方**避免导入环）注入现有 SOCKS5 路由，TUN 模式下 tun2socks 的单一出口天然走同一条路径；③ `vpn.enabled=false`（默认）时 `VPN==nil`，既有路径逐字节不变；④ `relay_only`（默认 true）经 **tailcat 的 `DERPOnly` 选项**（`vpnnode` 的 `PeerFaceOptions`/`ClientSetOptions` 透传）落到 tailscale 的进程级调试开关 `TS_DEBUG_ALWAYS_USE_DERP`：tailcat 在 `createEngine` 里、**创建 WireGuard 引擎之前**写它（magicsock 建 socket 时读取），因此 TUN 冲突只能在 `startVPN` 里强制、运行期只能拒绝（`Core.CheckVPNTunCompat`）；⑤ **内嵌 DERP 是私有端点**：它只接待来自**本机回环**的请求（`vpn.NewDERPMount` 按 `RemoteAddr` 判定，其余来源一律得到伪装页面，公网上没有任何"回答 DERP 协议"的路径），节点侧则由 `runner.newDERPDialer` 交给 tailcat 一个拨号器（`DERPDialer` 选项），把 tailcat 到 DERP 的每条 TCP 连接经 `StreamHandler.OpenTCPStream` 送进 easyss 隧道（`net.Pipe` 适配，复用生产路径上的中继；拨号上下文要 `context.WithoutCancel`——DERP 客户端在拨号返回后立刻取消它，而流的寿命是整个 DERP 连接）；服务端在握手阶段认出"目标就是我自己的对外 DERP 地址（domain + listen 端口）"后改拨 `127.0.0.1:<listen>`（`server/handler` 的 `localDERP`/`dialTarget`，该特例跳过后面的 SSRF 判定，因此只能由**完全匹配**触发）。**必须用拨号器而不是 `ALL_PROXY`**：tailcat 在 `createEngine` 里调用 `netns.SetEnabled(false)`，netns 的 SOCKS 包装根本不生效。**一个 region 下可以有多个中继**：节点地址内嵌的 DERP 节点就是 `servers[]` 里全部 `derp: true` 的条目（`vpn.BuildRegion` 变参，tailcat 按 `reg.Nodes` 顺序尝试，第一个连上的胜出），而节点**实际**能连上的只能是它当前隧道所落的那台服务端（localDERP 完全匹配），所以 `ClientConfig.ValidateDERPServer` 在 `runner.vpnOptions` 里拒绝"当前服务端不在声明列表"的配置（`log.Error` + VPN 本 session 缺席，代理照常）；对端地址内嵌的节点集合必须与本节点**相等**（`vpnnode.assertPeersShareDERPSet`）——只有相等才保证"无论隧道落在哪台服务端，地址里都有它"。TUN 因此不再需要为 DERP 主机装绕行路由（`vpnnode.Bypass`、`Config.BypassIPs` 与创建脚本的第 10/11 个位置参数已删除）；⑥ **服务端之间的 mesh**（`server.vpn.mesh_key` + `mesh_peers`，实现见 `vpn/mesh.go`）：每个中继为每个对端跑一个 URL 模式的 `derphttp.Client`（`MeshKey` + `WatchConnectionChanges` + `SetDialer`，首连观测把"连到了哪台/是不是自己"写成日志），把对端客户端的上下线变成 `derpserver.AddPacketForwarder/RemovePacketForwarder`，于是挂在不同中继上的客户端之间可以转发一跳（上游只转一跳、不跨 region）。三条形状约束：**必须经 easyss 隧道**（内嵌 DERP 只接待回环来源，所以每对端一个 SOCKS5 拨号器，缺省复用 `next_proxy.url`；直连对端公网端口只会拿到伪装页）、**必须落到对端自己的服务端**（TLS 校验 + `localDERP` 完全匹配共同保证，落错节点要么证书失败要么被识别为自连并告警）、**mesh_key 绝不进日志**（`sharedconfig.ParseVPNMeshKey`：64 位 hex 原样、其余字符串 SHA-256）。`vpn` 因此新增 `derphttp` 依赖，但仍**不引用 tailcat**（`vpn/deps_test.go` 继续把关）；配置校验在 `server/config.validateVPNMesh`（key/peers 必须成对、对端不能是自己也不能重复、无 proxy 时要求 `next_proxy.url`），装配在 `server/mesh.go`，`Server.Shutdown` 先取消 mesh（不再登记新映射）再停 HTTP、最后收 DERP。⑦ 对端名字由 DNS 静态钩子就地应答（A → overlay IPv4，AAAA → NOERROR 空应答，其余原样转发），语义收敛在 `dns.StaticReply`，但**必须接在两个前端上**：TUN 写进系统解析器的是**公网** DNS（`tunDNS`/`PreferredSystemDNS`），其查询经 tun2socks 以 53 端口到达 `client/proxy` 的 DNS 拦截器（`vpnStaticNames` 把它当作 `VPNRoute` 的可选能力），而 `client/dns` 的转发服务器只服务 `enable_forward_dns` 的 LAN 部署。Windows 上还有一个平台前提：它的解析器**从不把无点的单标签名字作为查询发给 DNS**（`Resolve-DnsName b` 直接返回 `ERROR_INVALID_NAME`，`ping b` 报 could not find host，而 `ping b.` 正常解析），因此无点的 `host_name` 即使在 TUN 下也解析不到，easyss 日志里连一条 DNS 查询都不会出现；`runner.startVPN` 在 Windows 上对无点的 `host_name` 打一条启动警告（`warnOnSingleLabelPeerNames`），对端名因此应当含点（`b.lan`），或在书写时加结尾点（`ssh user@b.`）

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
