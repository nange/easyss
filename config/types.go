package config

import "time"

// NextProtos 是 TLS 握手中通告的 ALPN 协议列表，与真实 Chrome 浏览器提供的一致
// （优先 h2，回退 http/1.1）。
var NextProtos = []string{"h2", "http/1.1"}

const (
	// 传输层/调度器默认值：超时基准（拨号/空闲）、连接池大小与流增长阈值、
	// 流量整形批处理窗口及 cover 预算上限。
	// conn_count_max / stream_threshold 的上下界紧随其后。
	DefaultTimeout         = 30
	DefaultConnCountMax    = 15
	DefaultStreamThreshold = 4
	DefaultBatchWindowMS   = 3
	DefaultCoverBudgetCap  = 16 * 1024 // 16KB

	// MinConnCountMax/MaxConnCountMax 界定 conn_count_max 的上下界：至少 2 个
	// 连接（调度器的双池划分需要为 bulk 池留出一个尾部槽位），至多 64，
	// 以免配置错误（或恶意超大）的值触发传输层槽位的大规模一次性分配。
	MinConnCountMax = 2
	MaxConnCountMax = 64

	// MaxStreamThreshold 界定 stream_threshold 的上限。调度器以 int32 从中派生
	// bulkThreshold（2 倍）和层容量位移（base << (level-1)），因此该上限使相关
	// 算术远离溢出——且与 MaxConnCountMax 对齐，超过连接上限的阈值本也不会触发扩容。
	MaxStreamThreshold = 64

	// 连接轮换：长期存活的 TCP+TLS 连接常被中间设备限速——尤其是在高峰时段——
	// 这也是重新连接后感觉又快了的缘故。连接超过任一上限的槽位不再接受新流，
	// 其空闲连接会被关闭，于是下一条流会拨号建立新连接（对用户无感）。
	DefaultConnLifetimeSec = 360               // 6min
	DefaultConnMaxBytes    = 256 * 1024 * 1024 // 256MB，双向（上下行）累计

	// ExpiringStreamDrainIdle 限定：在即将被淘汰（expiring 或 degraded）的槽位上，
	// 一条流在客户端提前关闭它之前可保持空闲的最长时间（见 relay.BidirectionalWithDrain）。
	// 否则，迟迟不退出的 keep-alive 与半关闭流会钉住该槽位的活跃计数，
	// 把轮换/退役推迟到完整的中继空闲超时（4 x DefaultTimeout = 120s）。
	// 完全静默 30s 即意味着该流实际上已经死亡——正常传输不可能暂停这么久，
	// 且 cover/padding 流量不会被中继计为活跃——因此关闭它不会打断任何东西。
	// 活跃流（有数据流动）绝不会被 drain。
	ExpiringStreamDrainIdle = 30 * time.Second

	// 启动预热：core 成功启动后立即预热传输层的调度连接池，使每种流量类别的
	// 第一条真实流都能复用已建立的连接，而不必付出冷启动代价（拨号 + TLS + HTTP/2）。
	// 预热在后台运行（见 runner.Run），因此这两个值都不会拖延启动。
	// WarmUpStartDelay 推迟探测的发出，让主机有时间完成网络路径的建立
	// （例如 Android VpnService 配置路由），避免探测仅因此类原因而失败；
	// 它是一个确定性的延迟，可由 Stop 取消，而非随机抖动。
	// WarmUpTimeout 限定探测阶段本身。两者都刻意不做用户配置：
	// 唯一可调开关是 transport.disable_warm_up。
	WarmUpTimeout    = 5 * time.Second
	WarmUpStartDelay = 500 * time.Millisecond

	// 由配置构建器、示例配置与运行时回退值共同使用的默认值。
	// 请把这些常量作为唯一事实来源：任何应用默认值的代码都必须引用常量，而非字面量。
	DefaultServerPort        = 443
	DefaultSocksPort         = 4080
	DefaultHTTPPort          = 5080
	DefaultProtocol          = "h2"
	DefaultMethod            = "aes-256-gcm"
	DefaultPrioritySlotRatio = 0.4
	DefaultCoverBudgetRatio  = 0.03
	DefaultProxyRule         = "auto"
	DefaultIPV6Rule          = "auto"
	DefaultLogLevel          = "info"

	// 重流检测：当满足以下任一条件时，一条流被视为"重流"（在丢包下独占其共享
	// TCP 连接），此后承载它的槽位停止接受新流，使交互流量（如页面刷新）不会被
	// 重传输拖累。
	//
	// 1. HeavyStreamThresholdBytes：快速、大体积的传输一旦累计超过该大小
	//    （任一方向）即被标记。
	// 2. HeavyStreamSlowThresholdBytes + HeavyStreamMinAge：在劣质链路上的慢速
	//    传输——即使不到 1MB 的资源也要数秒才能加载完成——在流存活足够久后即被
	//    标记，使隔离恰好在链路拥塞时及时生效。
	HeavyStreamThresholdBytes     = 1 * 1024 * 1024 // 1MB
	HeavyStreamSlowThresholdBytes = 300 * 1024      // 300KB
	HeavyStreamMinAge             = 5 * time.Second

	// 降级槽位检测：承载重流的槽位，若其下载吞吐量连续 DegradedPersistCycles 个
	// 健康检查周期低于 DegradedThroughputThreshold，则被*怀疑*降级，
	// 并通过在该槽位自身连接上的主动探测加以确认（见 EndpointProbe）。
	// 该标记在连续 DegradedRecoverCycles 个健康周期后清除。
	// 检测仅在链路 RTT 不超过 DegradedMaxRTT 时运行：拥塞的链路会让每条连接都变慢，
	// 此时退役连接只会徒增握手开销而无法恢复任何东西。
	// 该 RTT 是纯粹的客户端<->服务端路径 RTT（引导往返，不含源站延迟）；
	// 慢源站不再抑制检测。当服务端不支持探测时，怀疑直接标记槽位（遗留行为）。
	HealthCheckInterval         = 5 * time.Second
	DegradedThroughputThreshold = 80 * 1024 // 80KB/s
	DegradedPersistCycles       = 3
	DegradedRecoverCycles       = 2
	DegradedMaxRTT              = 800 * time.Millisecond

	// 主动槽位探测：降级槽位检测的确认步骤——被怀疑降级的槽位（被动吞吐量低于
	// DegradedThroughputThreshold）通过在其自身连接上下载预生成的随机负载来确认；
	// 只有探测结果缓慢才会将槽位标记为 degraded。探测只测量客户端<->服务端路径，
	// 因此慢源站或停滞但未关闭的流不再引发误判。
	ProbePayloadSize    = 128 * 1024       // 128KB，服务端启动时预生成
	ProbeTimeout        = 3 * time.Second  // 单次探测超时（含透明重拨）
	ProbeConfirmCycles  = 2                // 连续慢探测次数 → 标记 degraded
	ProbeCooldown       = 15 * time.Second // 同一 slot 两次探测最小间隔
	ProbeMaxPerInterval = 2                // 每个健康周期最多探测数
	ProbeLinkRefWindow  = 60 * time.Second // 链路参考速度有效窗口

	// 服务端上行流量控制：流级窗口限定单条上传流在途数据的上限，使其吞吐量大致
	// 封顶于 window/RTT。在 300ms 链路上，256KB 会把单流上传限制在约 6.8Mbps；
	// 1MB（stdlib 服务端默认值）可将其提升到约 26Mbps，而 4MB 的连接级窗口可避免
	// 聚合上传被约束为每条连接在途约 1MB。
	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 4 << 20   // 4MB，连接级上行窗口
	HTTP2ServerReceiveBufferPerStream     = 1 << 20   // 1MB，流级上行窗口（stdlib 服务端默认）

	// 客户端 HTTP/2 接收窗口，镜像 Chrome 的取值，使传输层在审查下表现得像真实浏览器。
	HTTP2ClientMaxReadFrameSize           = 1 * 1024 * 1024  // 1MB，Chrome MAX_FRAME_SIZE
	HTTP2ClientReceiveBufferPerConnection = 15 * 1024 * 1024 // ~15MB，Chrome 连接级窗口
	HTTP2ClientReceiveBufferPerStream     = 6 * 1024 * 1024  // 6MB，Chrome INITIAL_WINDOW_SIZE
	HTTP2ClientMaxDecoderHeaderTableSize  = 65536            // Chrome HEADER_TABLE_SIZE
	HTTP2ClientMaxResponseHeaderBytes     = 262144           // 256KB，Chrome MAX_HEADER_LIST_SIZE

	// TCP 流缓冲区大小：选取为每个批处理记录都保持在 64KB HTTP/2 帧上限以内
	// （客户端每记录打包 4 帧，服务端 2 帧）。
	TCPStreamBufferSize       = 15 * 1024 // 客户端，4帧/record (4*(15360+3)=61452 < 64KB)
	ServerTCPStreamBufferSize = 31 * 1024 // 服务端，2帧/record (2*(31744+3)=63494 < 64KB)

	// 端点路径：代理提供的唯一路径（强制 HTTP/2）；
	// 其余所有路径均返回 fallback HTML 页面。
	EndpointTCP   = "/v3/tcp"
	EndpointUDP   = "/v3/udp"
	EndpointICMP  = "/v3/icmp"
	EndpointProbe = "/v3/probe"

	// TUN 设备名默认值。由 client/tun.New（设备创建）与 util.IsTunIface
	// （识别 easyss TUN 设备，使直连拨号器永不绑定到它）共享的单一事实来源：
	// 两者都必须引用这些常量，绝不使用字面量。
	DefaultTunDeviceName       = "tun-easyss"
	DefaultTunDeviceNameDarwin = "utun9"
)

// DefaultStreamIdleTimeout 是构造器在未提供显式值（<= 0）时使用的回退 TCP 流空闲
// 超时。它通过 config.StreamIdleTimeout 从默认基础超时派生（4 x DefaultTimeout
// = 120s），使 timeouts.go 中的公式保持为唯一事实来源：正常路径从用户配置的
// 基础超时派生其超时，从不读取此变量。
var DefaultStreamIdleTimeout = StreamIdleTimeout(time.Duration(DefaultTimeout) * time.Second)

// DefaultUDPIdleTimeout 是构造器在未提供显式值（<= 0）时使用的回退 UDP 会话
// 空闲/读取超时。通过 config.UDPIdleTimeout 派生（2 x DefaultTimeout = 60s），
// 使其始终与正常路径从用户配置的基础超时派生的值一致。
var DefaultUDPIdleTimeout = UDPIdleTimeout(time.Duration(DefaultTimeout) * time.Second)

// DefaultDialTimeout 是构造器在未提供显式值（<= 0）时使用的回退出站拨号超时。
// 通过 config.DialTimeout 派生（DefaultTimeout/3 = 10s，限制在 [3s, 15s]），
// 使其始终与正常路径从用户配置的基础超时派生的值一致。
var DefaultDialTimeout = DialTimeout(time.Duration(DefaultTimeout) * time.Second)
