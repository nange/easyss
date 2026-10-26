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

服务端握手阶段解析 HANDSHAKE target（host→地址带 4×基础超时的短缓存，默认 120s；同一主机的并发流合并成一次解析），任一地址落在 LAN/私有/保留段即 400，并把解析结果传给拨号路径；拨号只拨这些已校验字面 IP，不再解析域名，因此 SSRF 检查与实际连接使用同一次解析，DNS-rebinding 无法翻转答案。next proxy 路径仍把域名交给上游解析（被墙域名依赖它），属已接受的残余风险。

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

### 14. 挂起复核：离差只产生嫌疑，在飞连接的判死必须一次真实往返

睡眠/VM 暂停会静默丢连接（NAT 过期，两端都以为活着），而 net/http 的空闲回收只作用于无活跃流的连接，常驻流（push/mtalk/DERP）会把死连接一直当作可用。判据是**墙钟推进减单调钟推进**（Go 单调钟在挂起期间冻结；ticker 实到间隔测不到）。三条不可动摇：

1. `suspendSampler` 只存一个标量 `suspendOffset`（墙钟 UnixNano − 单调读数）；存两个读数会在并发采样时撕裂成负离差。
2. 健康循环与开流路径共享同一采样器（`slotLifecycle.suspend`/`observeSuspend`），CAS 同时推进基线并认领观测，保证"一次挂起恰好一个观测者"；开流路径的采样不可省略（实测醒来后第一个开流常在 0.0s，早于健康周期）。
3. 吞吐基线重置走事件号（`suspendEvents`/`resetSamplingOnSuspend`），`lastHeavy` 只由健康循环写。

阈值 `SuspendDivergenceThreshold` 不判死在飞连接：空闲且已越过 net/http 空闲阈值（`IdleConnTimeout`）的连接直接退役——h2 用墙钟判 `tooIdle`，睡眠跳变后它们不可能再被复用，留着只会让下一次开流在同一代里再拨一条；其余有连接的槽位标记 `reverify`，判死在开流路径：`reverifySlot` 用一次 `HEAD /v3/probe`（`SuspendReverifyTimeout`）复核，活了复用，不通才按身份 CAS 失效；无法判定（无探测令牌）时保守放行。判活要剥掉调用方取消（否则本地关流会误杀健康连接）；失效只针对复核开始时的那一代；启发式本身有假阳性（NTP 跳变、VM 快照、含睡眠的单调钟），所以只能产生嫌疑。连带失败（`errClientConnForceClosed`）在 `isTransientStreamError` 归为瞬时错误记 Debug。

### 15. 规则解析与匹配只有一份实现

`rule` 包是"规则文件 → 匹配集合"的唯一入口，`client/router` 的 `direct_file`/`proxy_file` 与 `server/nextproxy` 的 `next_proxy_file` 都用它。`rule.Set` 同时持有 IP/CIDR/域名/glob/regexp 四类条目并自带锁（`MatchHost`/`MatchHostKind`/`HasDomain`/`AddIP`/`AddDomain`），router 的 `customDirect`/`customProxy` 各只是一个 `*rule.Set`。

归一化只有三个函数：匹配侧 `NormalizeHost`（去端口/尾点/小写）与 `canonicalIP`（IPv4-mapped 折叠），解析侧 `normalizeDomainKey`。DNS 缓存以小写为键、qname 带尾点、拨号目标是 `host:port`，三者必须在匹配前收敛成同一形态，否则会"命中缓存却路由到不同分支"。glob 与 `regexp:` 一律 `(?i)`（DNS 名大小写不敏感）。解析错误不静默：`ParseFile` 返回带行号的 `*rule.Error`，客户端只记启动告警（`CustomFileError`，内置规则仍生效），服务端 `next_proxy_file` 直接启动失败。`DomainSet` 承担内置 geosite 列表，`GeoSite` 只是别名。**不支持行尾注释**（`#` 在正则/glob 里可能合法）。

### 16. DNS 路由按 QNAME 决定，而不是按解析器地址

服务端 UDP 会话目标是解析器，但"直连还是走下一级代理"只有 QNAME 知道：目标是 53 端口的会话**推迟拨号**（`dnsSession=true` 时不拨，出站连接在第一条查询时建立）。DNS 部分集中在 `server/handler/udp_dns.go`，`udp.go` 只保留中继，两者只通过 `isDNSPort`/`observeDNSFrame`/`dialRoute` 交互；路由判定复用 next proxy（`routeForDomain` → `ShouldProxy`），`enable_udp=false` 时命中的域名退回直连。判定"是查询"不看 qtype（HTTPS/SVCB 等现代查询同样参与路由），A/AAAA 限制只用于缓存与答案学习；否则只发 HTTPS 记录的域名会绕过 next proxy。

同一会话路由可能变化：客户端把同一 socket 发往同一解析器的查询复用到同一条流（交换键是"来源地址 + 上游 + 应答目标"，与域名无关），因此一条服务端会话可能先后承载两个域名。`rebindRoute` **先按新路由拨号，成功后才替换连接**（失败保留旧连接，同一帧只拨一次；`conn`/`connRoute` 在 `installUpstream` 同一临界区替换，`closeUpstream` 一起清空），并为新连接补一个读取 goroutine（连接作为参数传入），"一条连接一个 reader"是结构性保证；旧连接之后报出的错误不会误杀新连接。重绑失败进入 `rebindCooldown`（10s），窗口内复用旧连接，在飞查询由客户端重试。`[UDP_DNS]` 的 `via_next_proxy` 是实际出站路径（重绑失败另带 `route_changed`/`route_pending`）；首拨失败没有连接日志，QNAME 由错误包装带进结果日志，重绑失败的 Warn 自带 `domain`。`[UDP] upstream connected` 按路由分字段：代理地址记 `proxy`、直连对端记 `remote`，DNS 会话带 `domain`。DNS over TCP 无需单独处理：它到服务端就是一个 UDP 数据报（`tcpDNSSession.resolveProxy` 复用代理 UDP 交换）。ICMP 不受影响。

### 17. DNS 拦截：判定与执行各一份，投递模型两份

`client/proxy` 的 DNS 拦截三层：①判定 `dnsInterceptor.plan` → `dnsPlan`（Block/IPv6 空应答/缓存命中/直连/代理），UDP/TCP 共用；②执行 `dns_exec.go`：`executeSync` 处理四条同步分支，`prepareProxied` 钳制 EDNS0 并封包，`finishProxied` 是代理应答的唯一后处理入口（规范化 EDNS0 → 按 ipv6 策略剥离 AAAA → 写缓存 → 记录 → 学习域名），`postProcessProxied` 只是字节流包装（UDP 改动后必须重新 Pack）；③投递：UDP 异步（`udpPool.receiveLoop` + `onData`），TCP 同步（`waitResponse` 阻塞）。投递模型不许合并（UDP 阻塞会丢多应答/重传语义）。缓存只接受 A/AAAA：Answer 里出现与 Question 同类型的 RR 才算正应答并按最小 TTL 加抖动；NODATA/NXDOMAIN 按 RFC 2308 取权威段 SOA 的 `min(TTL, MINIMUM)` 并封顶 5 分钟，无 SOA、其它 Rcode 或 TC=1 的截断应答不缓存，避免把临时无记录、CNAME-only NODATA 或截断结果变成负缓存。IPv6 被禁用（含 auto 尚无 IPv6）时，AAAA 查询在本地直接返回 NOERROR/NODATA，不走上游也不写缓存。

### 18. DNS 熔断判定只有一处

`client/dns/builtin.go` 的 `BuiltinRouteFor(hasFailover func() bool)` 返回三个互斥状态（`BuiltinRouteFirst`/`BuiltinRouteSkip`/`BuiltinRouteRetry`）。必须是三态：两个布尔时"熔断中但无兜底"与"健康"无法区分，"无视冷却重试"分支不可达。`hasFailover` 必须是惰性函数值：提前求值会让健康路径每次预解析都付一次系统 DNS 发现（darwin `networksetup` 约 48ms）。三条调用路径（`QueryWithBuiltinFirst`、`Cache.PrePopulateWithFallback`、`client.resolveServerIPV6`）共享判定但各自保留循环，因为调度与预算模型不同。唯一规则：**只有存在系统 DNS 兜底时才熔断内置池**（无兜底时熔断等于彻底中断，Android 上系统 DNS 不可见）；熔断已置位但当前无兜底时无视冷却，仍试内置池。
