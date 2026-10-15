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

	// MinTimeout/MaxTimeout 界定基础超时（秒）的合法区间：timeout 派生出 TCP/UDP
	// 空闲、拨号、DNS 响应与连接轮换（见 timeouts.go 的 NormalizeTimeout），因此
	// 不能随意设置——过小会让空闲流被频繁误杀，过大则让半开连接长时间占用资源。
	// 越界值取最近的边界。
	MinTimeout = 15
	MaxTimeout = 60

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
	// 轮换生命周期由基础超时派生（见 ConnLifetime），这里只有字节数上限。
	DefaultConnMaxBytes = 256 * 1024 * 1024 // 256MB，双向（上下行）累计

	// ExpiringStreamDrainIdle 限定：在即将被淘汰（expiring 或 degraded）的槽位上，
	// 一条流在客户端提前关闭它之前可保持空闲的最长时间（见 relay.BidirectionalWithDrain）。
	// 否则，迟迟不退出的 keep-alive 与半关闭流会钉住该槽位的活跃计数，
	// 把轮换/退役推迟到完整的中继空闲超时（8 x DefaultTimeout = 240s）。
	// 完全静默 30s 即意味着该流实际上已经死亡——正常传输不可能暂停这么久，
	// 且 cover/padding 流量不会被中继计为活跃——因此关闭它不会打断任何东西。
	// 活跃流（有数据流动）绝不会被 drain。
	ExpiringStreamDrainIdle = 30 * time.Second

	// 由配置构建器、示例配置与运行时回退值共同使用的默认值。
	// 请把这些常量作为唯一事实来源：任何应用默认值的代码都必须引用常量，而非字面量。
	DefaultServerPort = 443
	DefaultSocksPort  = 4080

	// DefaultHTTPPortOffset 是 http_port 缺省（0）时相对 socks_port 的固定偏移：
	// http_port = socks_port + DefaultHTTPPortOffset（默认 4080 + 1000 = 5080）。
	// 简化模式与完整模式共用同一推导（client/config.normalizeHTTPPort），因此这里
	// 刻意不再定义 DefaultHTTPPort：默认 HTTP 端口是推导结果，再留一份常量只会与
	// socks_port/offset 漂移（socks_port 改了而它没跟着改）。
	DefaultHTTPPortOffset = 1000

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

	// SlowRTTWarnThreshold 是单次纯路径 RTT 样本被额外记为 Warn 日志的阈值。
	// 托盘显示的是所有样本（每条流的引导往返 + 每次主动探测）的全局 EWMA，
	// 它只能说明"变慢了"，无法回答"是谁的往返慢"；越界的样本因此连同请求身份
	// （endpoint/target）与承载它的连接（槽位、活跃流数、槽位状态）一起打印。
	// 样本本身照常进入 EWMA，阈值只影响日志的可见性，不影响任何行为。
	SlowRTTWarnThreshold = 500 * time.Millisecond

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

	// 挂起复核：Go 的单调时钟在系统睡眠/VM 暂停期间冻结（darwin 上就是
	// mach_absolute_time，Apple 明确它不含睡眠时间），墙钟照走，因此"墙钟推进
	// 减去单调钟推进"就是进程被挂起的时长。超过 SuspendDivergenceThreshold 的
	// 离差只把槽位标记为"待复核"——它绝不关闭连接：健康连接会在开流前的一次
	// 往返判活（SuspendReverifyTimeout 内）中被原样放行，只有真的不可往返的
	// 连接才会被换掉。判据有假阳性（NTP/手动调时间向前跳、VM 快照恢复），
	// 这正是判死权必须留给一次真实往返的原因。
	//
	// 需要复核的原因是：挂起期间底层连接可能已被中间设备静默丢弃（两端都还
	// 认为它活着），而 net/http 的空闲回收与 tooIdle 判定都只作用于"没有活跃
	// 流"的连接，因此承载常驻流的槽位仍会把这条死连接当作可用。
	SuspendDivergenceThreshold = 30 * time.Second
	SuspendReverifyTimeout     = 2 * time.Second

	// 服务端上行流量控制。稳态吞吐 ≈ 窗口/RTT（HTTP/2 的发送方每 RTT 回收一次
	// 额度），因此流级窗口决定单条上传流的上限：4MiB-1 在 100/200/300ms 链路上
	// 分别约 335/168/112Mbps，而此前 stdlib 服务端默认的 1MB 只有 84/42/28Mbps。
	//
	// 两个窗口都取 net/http 文档允许的上界（文档原文是 "less than 4MiB"，因此
	// 4<<20 恰好越界——改前的连接级窗口就是这样，这次一并修正为 4<<20-1）。
	// 取文档内的值是有意的：实现目前并不校验这个上界（内部钳制区间是
	// [64KiB, MaxInt32] / [1, MaxInt32]，标准库自己的客户端默认值甚至就是 4<<20），
	// 但上传吞吐没有理由押在"实现不校验"上。
	//
	// 内存代价由**连接级**窗口决定，与流级窗口无关：每个收到的字节都要同时扣减
	// 连接窗口与流窗口（internal/http2 takeInflows），额度只在 handler 读走后才
	// 返还，因此"已收到但未消费"的请求体总量 ≤ 连接级窗口，与并发流数无关。
	// 连接窗口保持 4MiB-1 意味着服务端这条每连接上界与改动前持平（单流最坏占用
	// 由 1MB 升到 4MiB-1，仍被连接窗口兜住）；需要更高的单连接聚合上传上限
	// （例如多流测速）时显式调大 transport.h2_recv_buf_conn，并接受同比例上界。
	//
	// 与下行窗口的关系：客户端下行固定为 6MB/15MB（见下方 HTTP2Client*，镜像
	// Chrome 的伪装取值，不可配），上行这里由库文档上界决定——两个方向各自有
	// 唯一理由，数值因此不必相同。
	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 4<<20 - 1 // 4MiB-1，连接级上行窗口（= 每连接未消费请求体上界）
	HTTP2ServerReceiveBufferPerStream     = 4<<20 - 1 // 4MiB-1，流级上行窗口（= 单条上传流在途上限）

	// HTTP2ServerMaxConcurrentStreams 是服务端宣告的**每条连接**并发流上限。
	// SETTINGS_MAX_CONCURRENT_STREAMS 每个连接各宣告一次，不是服务器级总量；
	// 超限时标准库拒绝那条流（RST_STREAM）而不是断开连接，同时该连接并发运行的
	// handler 数受同一上限约束。Go stdlib 默认 250，而实测主流站点是 100/128
	// （Cloudflare/Amazon/Apple/淘宝/知乎/新浪/网易/WordPress 等），128 因此既
	// 贴近真实服务器，也把每连接的并发 handler 规模收敛约一半。
	// 可用 transport.h2_max_concurrent_streams 覆盖。
	HTTP2ServerMaxConcurrentStreams = 128

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
// 超时。它通过 config.StreamIdleTimeout 从默认基础超时派生（8 x DefaultTimeout
// = 240s），使 timeouts.go 中的公式保持为唯一事实来源：正常路径从用户配置的
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

// DefaultConnLifetime 是传输层构造器在未提供显式值（<= 0）时使用的回退连接生命周期。
// 通过 config.ConnLifetime 从默认基础超时派生（12 x DefaultTimeout = 360s），使
// timeouts.go 中的公式保持为唯一事实来源：正常路径（client.New）始终从用户配置的
// 基础超时派生其生命周期，从不读取此变量。
var DefaultConnLifetime = ConnLifetime(time.Duration(DefaultTimeout) * time.Second)
