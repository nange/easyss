# Easyss 架构与配置不变量

本文件与 [platform.md](platform.md) 只记录读代码不易看出、写错会静默出错的跨包契约；目录与构建/测试命令见 [AGENTS.md](../AGENTS.md)。改动传输、协议、加密、fallback、DNS 或配置前，读对应小节。

## 配置相关

- 默认配置 `config.json`，位于二进制同目录；简化模式/旧版配置由 `LoadConfig` 在内存中经 `BuildSimpleConfig` 转成 v3，不回写文件、不生成 `.bak`；完整模式 JSON 统一走 `ParseConfigJSON`。
- 入口：客户端 `client/config.ClientConfig`，服务端 `server/config.FileConfig`/`ServerConfig`。
- **线格式与运行时类型是同一份**：`shaper.Config` 与 `log.Config` 被客户端/服务端直接复用，`log.Init` 是日志配置唯一应用入口；不要再定义同形的 `ShaperConfig`/`LogConfig`。`Cover` 的 `IdleTimeout`/`MinSize`/`MaxSize` 是伪装层固定属性，保持 `json:"-"`。
- 字段命名：服务端 `server.host`（ACME 标识符：域名或公网 IPv4）、`server.port`（默认 443）、可选 `server.bind`；客户端完整模式 `servers[].host`。旧键由各自 `UnmarshalJSON` 兼容映射，新旧键同时出现报错。`ServerConfig.ListenAddr()` 是监听地址唯一格式化入口（`Port == 0` 回退 443）；`host` 不含端口的校验先于证书模式判定，手工证书模式同样适用；客户端由 `validateServers` 拒绝空/带端口的 `host`，地址拼装统一走 `net.JoinHostPort`（IPv6 自动加方括号）。
- 服务端加载与归一化统一走 `config.LoadConfig`（读文件 → 版本校验 → `applyDefaults` → `Validate` → `ResolveFilePaths`）；`applyDefaults` 负责没有其他 owner 的 0 值策略（`timeout`、`log.level`、`server.port`、`transport.h2_max_frame_size`/`h2_recv_buf_*`），`server.New` 也会调用 `FileConfig.Validate`。`buildHTTPServer` 只读归一化后的值；每连接并发流上限固定 128（`HTTP2ServerMaxConcurrentStreams`，不可配）；`shaper.*` 由 `shaper.Config.Normalize` 负责，不要出现第二份默认值。
- **证书来源只有一个判定入口**：`UsesManualCertificate`（手工 vs ACME）、`ACMESubjectIsIP`（IP 标识符）与 `validateTLS`（证书成对、ACME 下 `host` 必填、IP 只接受公网 IPv4 字面量）。公网性用 `util.IsLANIP`，故意比 certmagic 更严，不要放宽；IPv6/IPv4-mapped 被拒是因为地址都是 `IP:port` 形态（见要点 6）。
- `timeout` 是全部派生超时的唯一旋钮，范围 [15, 60] 秒（非正取 30，越界取最近边界），归一化只在 `config.NormalizeTimeout`/`TimeoutDuration`。
- **派生超时只在一处填零值**：`config.Timeouts` 由 `config.NewTimeouts` 派生，`Timeouts.Normalize` 只按 `Base` 补零值字段；每个公开构造器入口调用一次，其余地方直接读字段，不要再写 `if x <= 0`。SOCKS5 与 HTTP 两个入口必须拿到同一份 `Timeouts`（否则同一目标超时不一致）。
- 两处零值判断是语义不是默认值：`ProxyHandlerConfig.HandshakeTimeout <= 0` 表示沿用 `Timeouts.Base`；`udpPool.receiveLoop` 的 `respTimeout <= 0` 表示关闭读空闲。
- `http_port` 未配置时由 `socks_port` 推导（`+1000`），完整/简单模式同语义，只有 `client/config.normalizeHTTPPort` 一处实现；`socks_port=0` 不推导，`socks_port=0` + `http_port>0` 仍是启动错误（`runner.ErrSocksRequired`）。
- **本地代理端点地址只有一个来源**：监听用 `util.LocalProxyListenAddr`，本机消费方（HTTP 反向代理、TUN/helper、系统代理、托盘 `/stats`）用 `util.LocalProxyDialAddr`，`Socks5URI` 只是包装；`bind_all` 时分别是 `[::]` 与同族回环。不要再手拼 `127.0.0.1:<port>`（监听可能只接受 IPv6 回环）。`sysproxy.State.Enable`/`Disable` 接收完整地址，由 `sysproxy.Addr(cfg)` 推导。
- `tun_mtu`（完整 `local.tun_mtu`/简单同名，默认 1500，范围 [1280, 9000]）是设备与 netstack MTU 的唯一来源，归一化只在 `config.NormalizeTunMTU`。设备侧由创建脚本写入（第 9 个位置参数）；wintun 的 MTU 无法由 tun2socks 设置，只能靠 netsh；netstack MTU 小于设备 MTU 会静默丢弃超限包（UDP/ICMP/分片，TCP 因 MSS 通告不受影响）。
- `vpn.*`（客户端）与 `server.vpn.*`（服务端）只在 `vpn.enabled=true` 时参与运行期；`relay_only` 是"默认 true"的三态字段（指针，nil 视为 true），`peer_port` 由**访问器**派生（`ClientConfig.VPNPeerPort`，未配置时 `socks_port+2000`）而不是写进结构体——`applyDefaults` 没有错误返回值，也早于 `--local-port` 覆盖。**overlay 段没有配置项**：它只决定本机给对端分配哪个虚拟 IPv4、不进隧道，唯一来源是常量 `config.DefaultVPNOverlayCIDR`（经 `config.DefaultVPNOverlayPrefix()` 取得并校验）；`server.vpn.derp_addr`/`vpn.derp_addr`/`vpn.overlay_cidr` 都已移除（残留键打 WARN 后忽略）。细节见要点 19。

## 关键架构要点

### 1. 传输层

基于标准库 HTTP/2（`http.HTTP2Config`，Go 1.26+，不依赖 `golang.org/x/net/http2`）：初始 1 条连接（`MaxConnsPerHost=1`），按需懒加载到 `conn_count_max`，least-active 调度；TLS 用 uTLS Chrome 指纹。

**代 == 连接**：池与它拨出的连接打包成 `slotTransport{tr, conn}`，一代最多一条连接，连接关闭（`trackedConn.Close`）整代作废并把槽位换到新一代（`retireGeneration`/`advanceGeneration`）。因此流提交时记下的代（`http2Stream.gen`）就是它实际用过的连接——判死（`invalidateConn`）与判活（`ConnAlive`）只在自己那一代进行，不会误杀另一条流拨出的新连接。判死必须同时换池：net/http 没有关闭承载活跃流连接的 API，`CloseIdleConnections` 的收敛时机不可依赖。

例外：net/http 在连接达到服务端 `maxConcurrentStreams` 时会再拨一条（`MaxConnsPerHost=1` 挡不住）。服务端该上限固定 128、不可配，客户端用同一值判断"已满"。`HTTP2Config.StrictMaxConcurrentRequests` 在当前标准库会卡死，不能用（见 `slotTransport` 注释）。

### 2. 应用帧协议

HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER），`cipher_len:3 + ciphertext` 构成 CryptoRecord 边界。读路径由 `crypto.DecryptedReader.ReadFrame` 切记录后用 `protocol.DecodeFrame` 解帧；写路径由 `protocol.AppendFrame`/`EncodeFrames` 编码，经 `shaper` 批量加密写出。

### 3. 两阶段加密

Bootstrap 用 AES-256-GCM 加密初始握手帧（含目标地址与方法协商）；Session 用协商后的 AEAD（AES-256-GCM/ChaCha20-Poly1305），HKDF+salt 派生 C2S/S2C 独立密钥，每方向独立计数器 nonce。

### 4. 回落对抗

首个 CryptoRecord 解密/验证失败时回落成普通 HTML 首页；一旦发出 octet-stream 响应头，只能 close/RST。fallback 由 `handler.NewFallback(FallbackConfig)` 构造，在 `server.Start()` 一次性注入 `ProxyHandler`/`ProbeHandler` 与 `/` 路由；构造后只读、实例级缓存有界，没有包级可变状态，也没有"使用前必须调用"的顺序契约（未注入时回落到内置实例）。伪装两层：

- **部署级身份**（`fallback_random.go`）：每实例用 `crypto/rand` 派生稳定身份（主题色相族、站点名/导航/页脚/`Last-Modified`）；实例内所有客户端看到同一页面（静态站行为与页缓存前提），实例间互不相同。
- **HTTP 真实性**（`fallback_http.go`）：自动生成模式补齐 `Content-Length`/`Last-Modified`/`ETag`/`Accept-Ranges`，条件请求 304，浏览器式内容请求未知路径 404；目录/自定义/反代三种模式不受影响。

### 5. 端点

`POST /v3/tcp`、`/v3/udp`、`/v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）。`GET /v3/probe` 返回启动时预生成的随机数据，需 `x-es` 能力令牌（master key 派生），供客户端探测 slot 连接的真实下载速度。

### 6. 服务端与证书

需要 sudo（443 + ICMP）；证书用 certmagic ACME 或手动文件。ACME 标识符可以是域名或公网 IPv4：IP 证书（RFC 8738）必须短生命周期，`manageCert` 对 IP 显式请求 `shortlived` profile；它只能用 tls-alpn-01（dns-01 被禁止），因此公网 443 在签发与续期时必须可达。客户端侧 IP 分支跳过预解析/pinning，uTLS 不发 SNI、按 IP SAN 校验，**`sn` 必须留空**。

### 7. SSRF 防护与 DNS pinning

服务端握手阶段解析 HANDSHAKE target 一次，任一地址落在 LAN/私有/保留段即 400，并把解析结果传给拨号路径；拨号只拨这些已校验字面 IP，不再解析域名，因此 SSRF 检查与实际连接使用同一次解析，DNS-rebinding 无法翻转答案。next proxy 路径仍把域名交给上游解析（被墙域名依赖它），属已接受的残余风险。

### 8. 流量整形

`shaper` 把帧分批打包为 CryptoRecord，填充到固定档位（128/512/1500 字节），按预算比例注入 COVER 帧，批处理窗口默认 3ms。

### 9. 双向中继

`relay.Bidirectional` 共享空闲计时器，关闭时回调 exactly once；带 stall 检测与流量统计。

### 10. 统计

`stats` 维护全局原子计数器（streams/bytes/RTT/DNS 命中/fallback 等），经 HTTP 代理端口的 `/stats` 暴露（与 `/tun` 共用回环守卫）；计数器由 `counters`/`derivedCounters` 表驱动 Reset/Collect，漏登记会被测试拦住。

### 11. NextProxy

`server/nextproxy` 从 DNS 响应提取 CNAME 与解析 IP，动态加入代理列表。

### 12. 开机网络未就绪时的启动韧性

服务端域名预解析失败（`resolveServerDomain`）不是致命错误：进程照常启动并监听本地端口，降级为启动警告（`ErrServerDomainUnresolved`）；`retryServerDomain` 指数退避重试直到成功或 `Core.Stop`，每次重试前 `dns.ResetResolveState()` 清内置 DNS 熔断与系统 DNS 发现缓存，否则恢复要延迟数分钟。成功后关闭 `ServerDomainReady` 并把地址交给客户端（`publishServerIPs` → `SetServerIPs`）：拨服务端域名时优先拨这些 IP（TLS 仍用原域名）；单次失败只把本次拨号回退给系统解析器，不丢弃预解析结果（服务端换 IP 时先试一次再回退）。预解析的三层超时集中在 `client/dns/timeouts.go`（`dnsQueryTimeout`/`ResolveItemTimeout`/`PreResolveTimeout`，并预留 `WithSystemDNSFallbackReserve`）。TUN 以 `ServerDomainReady` 为前提（`canStartTunNow`）：未就绪不启动（避免解析递归/缺网关），网络恢复后由用户手动开启；`RefreshServerIPV6` 在启用前补齐服务器 IPv6。依赖与调参在派发 goroutine 前捕获（`serverDomainRetry`）。

### 13. 配置快照与运行期状态分离

`App.cfg` 是 `atomic.Pointer[ClientConfig]` 指向的不可变快照：菜单改动走 `App.updateConfig`（克隆→改→CAS），启动/切换用 `App.adoptConfig` 整体换装，只把快照交给新会话。运行期状态不进配置：TUN 是否生效由 `Client.SetTunMode`（`tunMode atomic.Bool`）告知，`local.enable_tun2socks` 只是"下次启动的偏好"（`client.New` 用它播种，`App.Start` 决定本会话后再覆盖）。服务器切换事务在 `App.restartServiceInSequence`；托盘只通过 `appUI` 读"系统代理/TUN 菜单"两个勾选状态，`session.run` 串行化"停→起/回滚"。

### 14. 挂起复核：离差只产生嫌疑，判死必须一次真实往返

睡眠/VM 暂停会静默丢连接（NAT 过期，两端都以为活着），而 net/http 的空闲回收只作用于无活跃流的连接，常驻流（push/mtalk/DERP）会把死连接一直当作可用。判据是**墙钟推进减单调钟推进**（Go 单调钟在挂起期间冻结；ticker 实到间隔测不到）。三条不可动摇：

1. `suspendSampler` 只存一个标量 `suspendOffset`（墙钟 UnixNano − 单调读数）；存两个读数会在并发采样时撕裂成负离差。
2. 健康循环与开流路径共享同一采样器（`slotLifecycle.suspend`/`observeSuspend`），CAS 同时推进基线并认领观测，保证"一次挂起恰好一个观测者"；开流路径的采样不可省略（实测醒来后第一个开流常在 0.0s，早于健康周期）。
3. 吞吐基线重置走事件号（`suspendEvents`/`resetSamplingOnSuspend`），`lastHeavy` 只由健康循环写。

阈值 `SuspendDivergenceThreshold` 只把活跃槽位标记 `reverify`，**绝不关连接**；判死在开流路径：`reverifySlot` 用一次 `HEAD /v3/probe`（`SuspendReverifyTimeout`）复核，活了复用，不通才按身份 CAS 失效；无法判定（无探测令牌）时保守放行。判活要剥掉调用方取消（否则本地关流会误杀健康连接）；失效只针对复核开始时的那一代；启发式本身有假阳性（NTP 跳变、VM 快照、含睡眠的单调钟），所以只能产生嫌疑。连带失败（`errClientConnForceClosed`）在 `isTransientStreamError` 归为瞬时错误记 Debug。

### 15. 规则解析与匹配只有一份实现

`rule` 包是"规则文件 → 匹配集合"的唯一入口，`client/router` 的 `direct_file`/`proxy_file` 与 `server/nextproxy` 的 `next_proxy_file` 都用它。`rule.Set` 同时持有 IP/CIDR/域名/glob/regexp 四类条目并自带锁（`MatchHost`/`MatchHostKind`/`HasDomain`/`AddIP`/`AddDomain`），router 的 `customDirect`/`customProxy` 各只是一个 `*rule.Set`。

归一化只有三个函数：匹配侧 `NormalizeHost`（去端口/尾点/小写）与 `canonicalIP`（IPv4-mapped 折叠），解析侧 `normalizeDomainKey`。DNS 缓存以小写为键、qname 带尾点、拨号目标是 `host:port`，三者必须在匹配前收敛成同一形态，否则会"命中缓存却路由到不同分支"。glob 与 `regexp:` 一律 `(?i)`（DNS 名大小写不敏感）。解析错误不静默：`ParseFile` 返回带行号的 `*rule.Error`，客户端只记启动告警（`CustomFileError`，内置规则仍生效），服务端 `next_proxy_file` 直接启动失败。`DomainSet` 承担内置 geosite 列表，`GeoSite` 只是别名。**不支持行尾注释**（`#` 在正则/glob 里可能合法）。

### 16. DNS 路由按 QNAME 决定，而不是按解析器地址

服务端 UDP 会话目标是解析器，但"直连还是走下一级代理"只有 QNAME 知道：目标是 53 端口的会话**推迟拨号**（`dnsSession=true` 时不拨，出站连接在第一条查询时建立）。DNS 部分集中在 `server/handler/udp_dns.go`，`udp.go` 只保留中继，两者只通过 `isDNSPort`/`observeDNSFrame`/`dialRoute` 交互；路由判定复用 next proxy（`routeForDomain` → `ShouldProxy`），`enable_udp=false` 时命中的域名退回直连。

同一会话路由可能变化：客户端把同一 socket 的所有查询复用到同一条流（交换键是"来源地址 + 上游"，与域名无关），因此一条服务端会话可能先后承载两个域名。`rebindRoute` **先按新路由拨号，成功后才替换连接**（失败保留旧连接，同一帧只拨一次；`conn`/`connRoute` 在 `installUpstream` 同一临界区替换，`closeUpstream` 一起清空），并为新连接补一个读取 goroutine（连接作为参数传入），"一条连接一个 reader"是结构性保证；旧连接之后报出的错误不会误杀新连接。重绑失败进入 `rebindCooldown`（10s），窗口内复用旧连接，在飞查询由客户端重试。`[UDP_DNS]` 的 `via_next_proxy` 是实际出站路径（重绑失败另带 `route_changed`/`route_pending`）；首拨失败没有连接日志，QNAME 由错误包装带进结果日志，重绑失败的 Warn 自带 `domain`。`[UDP] upstream connected` 按路由分字段：代理地址记 `proxy`、直连对端记 `remote`，DNS 会话带 `domain`。DNS over TCP 无需单独处理：它到服务端就是一个 UDP 数据报（`tcpDNSSession.resolveProxy` 复用代理 UDP 交换）。ICMP 不受影响。

### 17. DNS 拦截：判定与执行各一份，投递模型两份

`client/proxy` 的 DNS 拦截三层：①判定 `dnsInterceptor.plan` → `dnsPlan`（Block/缓存命中/直连/代理），UDP/TCP 共用；②执行 `dns_exec.go`：`executeSync` 处理三条同步分支，`prepareProxied` 钳制 EDNS0 并封包，`finishProxied` 是代理应答的唯一后处理入口（规范化 EDNS0 → 按 ipv6 策略剥离 AAAA → 写缓存 → 记录 → 学习域名），`postProcessProxied` 只是字节流包装（UDP 改动后必须重新 Pack）；③投递：UDP 异步（`udpPool.receiveLoop` + `onData`），TCP 同步（`waitResponse` 阻塞）。投递模型不许合并（UDP 阻塞会丢多应答/重传语义）。

### 18. DNS 熔断判定只有一处

`client/dns/builtin.go` 的 `BuiltinRouteFor(hasFailover func() bool)` 返回三个互斥状态（`BuiltinRouteFirst`/`BuiltinRouteSkip`/`BuiltinRouteRetry`）。必须是三态：两个布尔时"熔断中但无兜底"与"健康"无法区分，"无视冷却重试"分支不可达。`hasFailover` 必须是惰性函数值：提前求值会让健康路径每次预解析都付一次系统 DNS 发现（darwin `networksetup` 约 48ms）。三条调用路径（`QueryWithBuiltinFirst`、`Cache.PrePopulateWithFallback`、`client.resolveServerIPV6`）共享判定但各自保留循环，因为调度与预算模型不同。唯一规则：**只有存在系统 DNS 兜底时才熔断内置池**（无兜底时熔断等于彻底中断，Android 上系统 DNS 不可见）；熔断已置位但当前无兜底时无视冷却，仍试内置池。

### 19. 节点组网（VPN）

两个包按"是否引用 tailcat"分界，这是硬约束不是组织偏好：`vpn` 只放共享原语（内嵌 DERP 中继、region、mesh、状态目录与密钥持久化），服务端只依赖它；`vpn/node` 才有 tailcat 身份、overlay、对端面与访问侧。`vpn/deps_test.go` 用 `go list -deps` 钉住"`vpn` 的依赖图里没有 tailcat"，任何对 tailcat 的引用都会把 WireGuard 引擎与 gVisor netstack 拖进服务端二进制。拓扑是"每个访问侧为每个对端跑一个 tailcat Client，对端跑 tailcat Server"——tailcat 客户端不接受入站、Server 没有 netstack 拨号 API，因此对端身份与虚拟 IP 都由 tailcat 公钥确定性派生，零控制面、零 IP 分配。

对端面的 UDP **不复用** SOCKS5 的 ASSOCIATE（那条路径会把中继 socket 绑到 tailcat 的 ULA 上，宿主没有该地址），而是由 `vpnnode.EncodeUDPTarget` 定义一次性目标头：第一个数据报带长度前缀的 `host:port` 文本，其后全是原始载荷。目标头与首段载荷在同一条数据报里，因此对端读首包的缓冲区是 `目标头上限(1+255) + tailcat.MaxUDPPayload`：读满缓冲区（超限）的数据报**丢弃并告警**，绝不转发剪短后的载荷（UDP 读在缓冲区处截断且不报错，转发出去就是静默的数据损坏）；访问侧在写入前按 `tailcat.MaxUDPPayload` 拒绝超限载荷，且首包写失败时不消耗目标头（否则这条流之后每个数据报都不带目标，对端会一直拒绝）。对端面直接复用 `client/proxy.Socks5Server`（`router.NewDirectOnly()` + `DisableDNSIntercept` + 拨号固定到本机回环），内层 CONNECT 目标恒为字面 `127.0.0.1:<peer_port>`，对端只可能拨自己的 loopback、不可能成为内网跳板。`Socks5Server.Serve` **取得**监听器所有权（Close 必须关闭它，否则重启后端口仍被占、下一次切换服务器必然失败），`ServeBorrowed` 才是不持有的那个：VPN 对端面用的是 tailcat 在 gVisor netstack 里的监听器，本来就不属于宿主。访问侧不新增监听端口，而是经 `Socks5Options.VPN`（`client/proxy.VPNRoute`，**接口定义在消费方**，否则与 `vpn/node` 形成导入环）注入现有 SOCKS5 分流；`decide` 在 router **之前**判定对端（host_name 与 overlay IP 只有本机认识），TUN 模式下 tun2socks 的单一出口天然走同一条路径。`Lookup` 返回**规范名**：同一个对端按 host_name 与按 overlay IP 访问必须落在同一条隧道流上，否则两种写法各建一条。`vpn.enabled=false`（默认）时 `VPN==nil`，既有路径逐字节不变。

`relay_only`（默认 true）经 tailcat 的 `DERPOnly` 落到 tailscale 的进程级调试开关 `TS_DEBUG_ALWAYS_USE_DERP`：tailcat 在**创建 WireGuard 引擎之前**写它（magicsock 建 socket 时读取），所以与 TUN 的冲突只能在 `startVPN` 里强制、运行期只能拒绝（`runner.Core.CheckVPNTunCompat`，两条 TUN 启动路径各一次），等 Server/Client 起来后再改对已绑定的 socket 无效。内嵌 DERP 是**私有端点**：`vpn.NewDERPMount` 按 `RemoteAddr` 只接待本机回环来源，其余来源一律得到伪装页面；节点侧由 `runner.newDERPDialer` 通过 `DERPDialer` 选项把每条 DERP 连接经 `StreamHandler.OpenTCPStream` 送进 easyss 隧道（`util/netpipe` 的带缓冲内存管道，缓冲 `config.DERPPipeBufferSize`；拨号上下文要 `context.WithoutCancel`，DERP 客户端在拨号返回后立刻取消它）。这里不能用 `net.Pipe`（无缓冲，背压直接打在 magicsock 那个 32 深、满了丢最旧的写队列上），也不能用 `ALL_PROXY`（tailcat 在 `createEngine` 里 `netns.SetEnabled(false)`，`netns.NewDialer` 因此返回未包装的拨号器）。`util/netpipe` 自己还有两条硬约束：deadline 必须绝对且可随时改写，单次写入不能大于缓冲容量、必须按容量分片。上游缓冲与中继队列深度必须**匹配着看**：队列 32 帧时把管道缓冲从无缓冲加到 128KB，吞吐反而从 594 KB/s 掉到 127 KB/s；128KB 是实测曲线上的平台，不要"越大越好"。服务端启动时要求 `server.bind` 是通配或回环地址（`loopbackListenAddr`，否则报配置错误：DERP 与代理共用同一个 HTTPS 监听，只绑某一个非回环网卡时回环改拨不可达）；回环拨号地址必须按实际绑定推导（绑的是 `127.0.0.2` 这类回环字面量时就用它本身，只有通配监听才落到同族回环），运行期在握手阶段认出"目标就是我自己的对外 DERP 地址"后改拨该地址（`server/handler` 的 `localDERP`/`dialVia`，该特例跳过后面的 SSRF 判定，因此只能由**完全匹配**触发，且只可能由持有 master key 的节点经隧道发起）。TUN 因此不再需要为 DERP 主机装绕行路由（旧版的 `Bypass`/`BypassIPs` 与创建脚本的第 10/11 个位置参数已删除）。

**DERP 节点是一组而不是一台**：`servers[]` 里全部 `derp: true` 的条目共同构成同一 region 下的多个中继（`vpn.BuildRegion` 变参，tailcat 按 `reg.Nodes` 顺序尝试，第一个连上的胜出），最多 `config.MaxVPNRelays`（3）条、推荐 1-2 条，计数按 `config.CanonicalDERPAddr` 规范化去重后算（超限由 `ClientConfig.ValidateDERPRelays` 在 `LoadConfig`/`ParseConfigJSON` 里拒绝启动，且只在 `vpn.enabled=true` 时校验）；没有任何标记时回退**当前连接的服务端**。两侧都**没有** `derp_addr` 配置项：服务端由 `server.host` + `server.port` 推导（`FileConfig.ResolveDERPAddr`），客户端只能由 `derp` 标记派生，残留的旧键由 `LoadConfig` 打一条 `was removed and is ignored` 的 WARN 后忽略。节点**实际**能连上的只能是它当前隧道所落的那台服务端，因此 `ClientConfig.ValidateDERPServerAddr(current)` 拒绝"当前服务端不在声明列表"的配置（`log.Error` + VPN 本会话缺席，代理照常），判据的 `current` 是**显式入参**而不是隐式取 `DefaultServer()`：它由运行中会话给出（会话起点解析一次并记进 `Core.ServerAddr`，托盘勾选只是它的界面镜像）。该拒绝带错误身份 `clientconfig.ErrCurrentServerNotDERPRelay`，托盘在**启动**与**切换服务器**两条路径上都以系统通知告知（`startupWarningNotice`/`startupWarningText`/`vpnRefusalText`，文案点名 `Core.ServerAddr`；VPN 之外的启动警告在切换路径上仍只写日志）。对端 `peers[].address` 内嵌的 DERP 节点集合必须与本节点**相等**（`vpnnode.assertPeersShareDERPSet`，顺序无关），地址与发布的 `<exe>/vpn/peer.txt` **必须是完整展开格式**（短格式会去拉官方 DERPMap，违反零外部依赖，`vpnnode.AssertFullAddr` 在配置校验与发布前各拦一次）。

内嵌中继的**每客户端待发队列深度**由 `server.vpn.derp_send_queue_depth` 配置（0 取 `config.DefaultDERPSendQueueDepth`，钳制到 [Min, Max]，归一化在 `config.NormalizeDERPSendQueueDepth`，落位在 `vpn.NewDERPServer`）：它是中继路径上唯一能存住"尚未被确认的数据"的地方，单条 TCP 流的吞吐 ≈ 深度 × 每帧约 1.4KB / 端到端 RTT（内层 RTT 240ms 时：32 帧 → 127 KB/s，256 帧 → 695 KB/s）。它只能经 fork 的进程级开关 `TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH` 落位（`derpserver.New` 只在构造时读一次），落位方式是**构造前临时写入、构造后立刻还原**（`vpn.applySendQueueDepth`）：那是实现细节而不是配置面，进程环境里预先设置的同名值既不生效也不会被改动。**服务端之间的 mesh**（`server.vpn.mesh_key` + `mesh_peers`，实现见 `vpn/mesh.go`）为每个对端跑一个 URL 模式的 `derphttp.Client`（`MeshKey` + `WatchConnectionChanges` + `SetDialer`），把对端客户端的上下线变成 `derpserver.AddPacketForwarder/RemovePacketForwarder`，于是挂在不同中继上的客户端之间可以转发一跳（上游只转一跳、不跨 region）。三条形状约束：必须经 easyss 隧道（内嵌 DERP 只接待回环来源，所以每对端一个 SOCKS5 拨号器，缺省复用 `next_proxy.url`）、必须落到对端自己的服务端（TLS 校验 + `localDERP` 完全匹配共同保证）、`mesh_key` 绝不进日志（`config.ParseVPNMeshKey`：64 位 hex 原样、其余字符串 SHA-256）。配置校验在 `server/config.validateVPNMesh`（key/peers 成对、对端不能是自己也不能重复、中继总数不超过 `MaxVPNRelays`、无 proxy 时要求 `next_proxy.url`），装配在 `server/mesh.go`，`Server.Shutdown` 先取消 mesh（不再登记新映射）再停 HTTP、最后收 DERP——DERP 的连接全部是 Hijack 走的，`http.Server.Shutdown` 明确不管也不等待被 Hijack 的连接。

对端名字由 DNS 静态钩子就地应答（A → overlay IPv4，AAAA → NOERROR 空应答，其余原样转发），语义收敛在 `dns.StaticReply`，但**必须接在两个前端上**：TUN 写进系统解析器的是公网 DNS（`app.tunDNS`/`PreferredSystemDNS`），其查询经 tun2socks 以 53 端口到达 `client/proxy` 的 DNS 拦截器（`vpnStaticNames` 把它当作 `VPNRoute` 的可选能力，动作是 `dnsActionStatic`），而 `client/dns` 的转发服务器只服务 `enable_forward_dns` 的 LAN 部署。Windows 上还有一个平台前提：它的解析器**从不把无点的单标签名字作为查询发给 DNS**，因此无点的 `host_name` 即使在 TUN 下也解析不到（`ping b.` 可以），`runner.startVPN` 在 Windows 上对它打一条启动警告（`warnOnSingleLabelPeerNames`）。

CLI 面是 `easyss vpn`（`cmd/easyss/internal/vpncmd`，与 `selfupdate`/`tun-helper` 一样在 flag 解析之前分派）：`identity [--json]` 打印 client nodekey 与节点地址，`regen [--node] [--client] [--dry-run] [--json]` 重新生成身份。**地址是 `(身份, 中继集合)` 的纯函数、不落盘**，改了 `servers[]` 的 derp 标记只需重新执行一次；`regen` 换的是身份本身，旧身份先备份成 `<file>.bak`（固定名、每次覆盖，因此每个身份文件最多只留一份备份 = 上一次生效的身份）。`runner.RegenerateVPNIdentity` 的顺序是**先生成 → 再推导 → 最后才写**：推导不出地址必须在任何文件被改写之前失败，否则本节点会丢掉唯一有效地址而运维什么也没得到；`--dry-run` 只预览一份新身份（密钥每次调用现生成，因此预览值不等于随后真写的那次，且不写任何文件）。`vpn identity` 的输出格式有契约（`vpncmd_test.go` 逐行固定、含空行）：身份值按“一次只讲一件事”分块、块间空一行，因为这些值都要人手动复制到对端；附注与“旧值”按 `VPNRegenResult.Replaced`（实际换掉的那一半）选，而不是按请求的 `Kinds`。终端文案是中文，但配置字段名、命令名与 flag 保持原文（运维要拿它们去搜配置或复制命令）。路径观测用 `vpnnode.PathStatus` 的 `DiscoPing` 而不是 tailcat 的 `Client.Ping`：后者总是回报经中继，证明不了 `relay_only`；而 `Direct == false` 只说明这一次没走直连，`Direct == true` 才是确凿的（那次直连真的可用）。`vpn.LoadOrCreate` 绝不静默覆盖（坏文件只提示跑 `easyss vpn regen`），读入时校验身份文件的两半自洽（`Private.Public()` 必须等于 `Public.ServerPublic`：服务端只用私钥，而地址通告的是公钥，不一致时只有对端握手失败），`vpn.RegenerateFile` 是唯一被允许覆盖身份文件的入口，重新生成 node identity 时必须同步重写 `peer.txt`（否则运维照旧文件抄给对端的是内嵌上一个 preshared key 的地址）；`vpn.IdentityRegenPending` 用**内容比较**（不是 mtime）判断"当前身份与备份不同"。状态目录 `<exe>/vpn/`（`node-identity.json`、`client.key`、`peer.txt`）三份文件都是 0600、目录 0700，client key 必须跨重启稳定（`allow_clients` 的前提）；地址令牌**绝不进日志**（`runner.startVPN` 只打 `address_file`/`client_nodekey`/`derp_addrs`，全量地址只经 `easyss vpn identity` 与 `peer.txt` 交付）。

**运行期顺序与开关。** VPN 对端流量必须先于公网路径的各道门禁判定（`disable_quic` 的 443 屏蔽、IPv6 策略门、链路本地丢弃、53 端口 DNS 拦截），否则发往对端 443 的数据报会被静默丢弃、53 查询会被按域名重新分流；对端面自己必须打开 `DisableDNSIntercept`（对端 53 是普通服务端口）。对端 UDP 会话键是 `vpn_` + 客户端地址 + 对端规范名 + **目标端口**：目标在首个数据报里固化，键里少了端口就会把第二个端口的数据报投到第一个端口上。`relay_only` 的 TUN 强制只在 `peers > 0` 时发生（没有对端就没有可关闭的直连路径）。`StopVPN` 与**启动失败的回收**共用同一层超时兜底（`closeVPNStackWithin`）：magicsock 在 DERP-only 下重建 UDP socket 时会把已 park 的 receive goroutine 遗留在永不关闭的 `blockForeverConn` 上，wireguard-go 的 `Device.Close` 停在 `netc.stopping.Wait()`，因此关闭链可能永久阻塞；超时后仍要返回并把 stack 从 Core 摘掉。VPN 启动失败时 `Core.ServerAddr` 仍记录会话实际使用的服务器；只有带 `ErrCurrentServerNotDERPRelay` 的启动警告弹系统通知，其余在切换路径上只写日志。

**配置面的硬约束。** `vpn.peer_port` 的派生偏移必须大于 `http_port` 的 `+1000`，否则同一 `socks_port` 派生的两个端口会重叠（对端面只在 tailcat 的 gVisor netstack 内监听、不占宿主端口，所以不需要预留）。overlay 段选 `198.19.0.0/24`（RFC 2544）而不是 CGNAT 的 `100.64.0.0/10`：CGNAT 段在物理接口上常有更具体的 on-link 路由，会把 overlay 流量压回物理网卡；槽位表按 `2^(32-bits)` 预分配（`/16` = 65534 个槽位，`0.0.0.0/0` 会在启动时申请 4GiB 并清零），因此前缀长度被钳在 `[/16, /30]`。`DefaultVPNRegionID` 必须非零（`tailcat.Server.Start` 拒绝 0）并避开 Tailscale 官方的 1..~30 与 ~900 段。服务端 DERP 地址只由 `server.host` + 端口推导、且必须与每个节点 `servers[]` 的 `derp` 条目逐字一致：做成配置项只会提供一个"服务端以为自己叫什么、节点写在别处"的失配开关。`HostName` 只在访问侧本地使用，`Address` 才是唯一跨节点凭据；名字会被用在 URL、`host:port` 与 DNS 问题名三处，写成 FQDN（`"b."`）时只有 DNS 问题名会自动去根点，于是能过校验却永远匹配不上。`StaticNameTTL=60` 是因为 overlay 地址按公钥线性探测分配，增删对端可能移动地址，短 TTL 缩小旧地址指向错误对端的窗口。`ParseVPNMeshKey` 两侧不一致不会报错（对端只被当成普通 DERP 客户端，mesh 静默建不起来）。身份文件必须持久化整个 `ConnInfo`——disco 公钥无法从 node 私钥推导——且 client key 必须显式设置并跨重启稳定：tailcat 不设置时会生成进程内临时 key，对端 `allow_clients` 每次重启后失效，失败表现只是"连不上"；Windows 上 Go 的 `Perm()` 由只读属性合成，POSIX 权限断言在那里没有意义。

**CLI 面的契约。** `easyss vpn` 的退出码是 3（执行失败）、2（用法错误），1 专留给代理启动失败；`-c/--config` 只能预扫描（参数错误必须早于配置加载，取值规则与 flag 包一致）。`vpn identity` **不执行**"当前服务端必须是中继"的启动门禁，只打一行 warning（门禁在 `runner.vpnOptions`）；它走 `vpn.LoadOrCreate`，因此"只读"命令也可能创建缺失的密钥文件（不改动已生效身份）。`--json` 的字段名映射配置字段（`client_nodekey`→`vpn.allow_clients`、`address`→`vpn.peers[].address`），`old_*` 是替换前的值，`has_node_identity=false` 时 `address` 为空、原因在 `address_error`。`regen` 部分失败也要返回非 nil 结果并带 `Replaced` 与备份路径，CLI 在错误路径上逐个打印"哪个文件已被替换、备份在哪"；回滚就是把 `.bak` 拷回原名。

**体积与实测。** 两个包的分界有可测的体积含义（darwin/arm64、`-s -w`）：只引 `derpserver` 约 6.46 MiB，只引 tailcat 约 16.15 MiB，服务端因此 13.03 → 27.19 MiB（+109%）；`vpn/deps_test.go` 用 `go list -deps "."` 检查**传递**依赖（只看本文件 import 挡不住间接引入；`.` 而非 `./...`，因为 `vpn/node` 本就依赖 tailcat）。吞吐基线（单程 60ms → 内层 RTT ≈240ms；连续 5 次、每次新建内层连接、各传 1MB 取中位数）：

| 形态 | 32 帧 | 256 帧 | 1024 帧（默认） |
|---|---|---|---|
| 直连 | — | — | 59834 KB/s |
| DERP 连接 = 普通 TCP | 593 | — | 695 KB/s |
| DERP 连接 = netpipe 128KB（生产） | 127 | 695 | 696 KB/s |
| DERP 连接 = 无缓冲 net.Pipe | 594 | — | 696 KB/s |

默认深度下三种连接形态收敛到约 696 KB/s，因此这份数据**不能**用来给"抬高 magicsock 那个 32 深写队列"背书；队列深度只在"上游缓冲很小"时决定性（netpipe：32 帧 127、256 帧 695 KB/s）；上游缓冲不能超过瓶颈队列（32 帧 ≈45KB 时 128KB 管道把 594 压到 127，多出的缓冲被换成丢包）。长连接测稳态会随机踩内层 TCP RTO 退避（稳定在 3.4 KB/s），同一配置跨次可差三个数量级，所以基线取中位数；门槛按形态设定（生产形态实测 881、无缓冲 175、深度回退 32 时 139）。基准由 `EASYSS_VPN_THROUGHPUT_TEST=1` 开启，`EASYSS_VPN_TPUT_SHAPE=direct|tcp|netpipe|bufpipe`（默认 bufpipe）、`EASYSS_VPN_TPUT_OW_MS`（默认 60，内层 RTT≈4×单程）、`EASYSS_VPN_TPUT_DEPTH` 可调；**一个进程只测一个配置**（同进程连续测多个配置会互相干扰）。
