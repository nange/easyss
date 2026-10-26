package config

import "time"

// NextProtos 必须与真实 Chrome 的 ALPN 列表和顺序一致。
var NextProtos = []string{"h2", "http/1.1"}

const (
	DefaultTimeout         = 30
	DefaultConnCountMax    = 15
	DefaultStreamThreshold = 4
	DefaultBatchWindowMS   = 3
	DefaultCoverBudgetCap  = 16 * 1024 // 16KB

	// MinTimeout/MaxTimeout 界定基础超时（秒）区间，所有派生超时共享它，越界取最近边界。
	MinTimeout = 15
	MaxTimeout = 60

	// MinConnCountMax 至少为 2：双池调度要给 bulk 池留一个尾部槽位，其余上限防住配置错值
	// 触发的大规模一次性分配与算术溢出。
	MinConnCountMax = 2
	MaxConnCountMax = 64

	MaxStreamThreshold = 64

	// 长期存活的连接会被中间设备限速，超过上限的槽位停止接受新流并关闭空闲连接。
	DefaultConnMaxBytes = 256 * 1024 * 1024 // 256MB，双向累计

	// ExpiringStreamDrainIdle 是即将被淘汰的槽位上一条流可保持空闲的最长时间，超过即提前
	// 关闭：否则 keep-alive 与半关闭流会钉住活跃计数，把轮换推迟到整个中继空闲超时。
	ExpiringStreamDrainIdle = 30 * time.Second

	DefaultServerPort = 443
	DefaultSocksPort  = 4080

	// DefaultHTTPPortOffset 是 http_port 缺省（0）时相对 socks_port 的偏移（+1000），推导只有
	// client/config.normalizeHTTPPort 一处实现。
	DefaultHTTPPortOffset = 1000

	DefaultProtocol          = "h2"
	DefaultMethod            = "aes-256-gcm"
	DefaultPrioritySlotRatio = 0.4
	DefaultCoverBudgetRatio  = 0.03
	DefaultProxyRule         = "auto"
	DefaultIPV6Rule          = "auto"
	DefaultLogLevel          = "info"

	// 满足任一条件即标记重流：承载它的槽位随即停止接受新流，交互流量不再被重传输拖累。
	// 慢速阈值只有配合最小存活时间才成立，劣质链路上的小传输也会持续很久。
	HeavyStreamThresholdBytes     = 1 * 1024 * 1024 // 1MB
	HeavyStreamSlowThresholdBytes = 300 * 1024      // 300KB
	HeavyStreamMinAge             = 5 * time.Second

	// 降级检测：承载重流的槽位连续若干健康周期吞吐低于阈值即被怀疑降级，并在自身连接上
	// 主动探测确认。只在链路 RTT 不超过 DegradedMaxRTT 时运行，否则每条连接都会变慢。
	HealthCheckInterval         = 5 * time.Second
	DegradedThroughputThreshold = 80 * 1024 // 80KB/s
	DegradedPersistCycles       = 3
	DegradedRecoverCycles       = 2
	DegradedMaxRTT              = 800 * time.Millisecond

	// 越界的 RTT 样本额外记 Warn，阈值只影响日志可见性，样本照常进入 EWMA。
	SlowRTTWarnThreshold = 500 * time.Millisecond

	// 被怀疑降级的槽位通过在自身连接上下载预生成的随机负载确认，因此只测客户端到服务端的
	// 路径，慢源站或停滞的流不会引发误判。
	ProbePayloadSize    = 128 * 1024       // 128KB，服务端启动时预生成
	ProbeTimeout        = 3 * time.Second  // 单次探测超时（含透明重拨）
	ProbeConfirmCycles  = 2                // 连续慢探测次数 → 标记 degraded
	ProbeCooldown       = 15 * time.Second // 同一 slot 两次探测最小间隔
	ProbeMaxPerInterval = 2                // 每个健康周期最多探测数

	// ProbeHoldWindow 是探测判定"该槽位无责"（连接健康）后的静默期：慢源站会稳定复现，
	// 没有它会按 ProbeCooldown 的节拍无限重探；代价是真实劣化最多晚一个静默期才进入探测。
	// 取 4 个被动起疑周期，与 HealthCheckInterval 一起缩放。
	ProbeHoldWindow = 4 * DegradedPersistCycles * HealthCheckInterval
	// ProbeMaxBackoff 是"探测得不出结论"时的最大重试间隔（按连续次数翻倍退避）。
	ProbeMaxBackoff = 10 * time.Minute

	// 挂起复核：墙上时钟推进与单调钟推进之差即挂起时长。超阈值只标记待复核，不判死在飞
	// 连接；空闲且已越过 net/http 空闲阈值的连接直接退役（h2 的墙钟 tooIdle 不会再复用）。
	// 判据有假阳性，判死权留给开流前的一次真实往返。
	SuspendDivergenceThreshold = 30 * time.Second
	SuspendReverifyTimeout     = 2 * time.Second

	// 服务端上行流量控制：窗口取 net/http 文档允许的上界（原文 "less than 4MiB"，4<<20 恰好越界），
	// 每字节同时扣减连接与流窗口，所以每连接未读走的请求体不超过连接级窗口。连接级窗口 ≥ 流级窗口。
	HTTP2ServerMaxReadFrameSize           = 1<<24 - 1 // 16MB-1，nginx/Cloudflare 主流值
	HTTP2ServerReceiveBufferPerConnection = 4<<20 - 1 // 4MiB-1，连接级上行窗口
	HTTP2ServerReceiveBufferPerStream     = 4<<20 - 1 // 4MiB-1，流级上行窗口

	// HTTP2ServerMaxConcurrentStreams 不开放配置：它是 SETTINGS 里可被动的指纹，而客户端用
	// 该值判断连接是否已满，调小会让客户端在池内再拨一条连接，破坏"一个槽位一条连接"。
	HTTP2ServerMaxConcurrentStreams = 128

	// 镜像 Chrome 的接收窗口，使传输层在审查下表现得像真实浏览器。
	HTTP2ClientMaxReadFrameSize           = 1 * 1024 * 1024  // 1MB，Chrome MAX_FRAME_SIZE
	HTTP2ClientReceiveBufferPerConnection = 15 * 1024 * 1024 // ~15MB，Chrome 连接级窗口
	HTTP2ClientReceiveBufferPerStream     = 6 * 1024 * 1024  // 6MB，Chrome INITIAL_WINDOW_SIZE
	HTTP2ClientMaxDecoderHeaderTableSize  = 65536            // Chrome HEADER_TABLE_SIZE
	HTTP2ClientMaxResponseHeaderBytes     = 262144           // 256KB，Chrome MAX_HEADER_LIST_SIZE

	// 读缓冲上限会被 netbuf 向上取到池的 2 的幂档位（15360→16384，31744→32768），
	// "每个记录几帧"由取整后的档位决定。
	TCPStreamBufferSize       = 15 * 1024 // 客户端，满档 3 帧/record
	ServerTCPStreamBufferSize = 31 * 1024 // 服务端，满档 1 帧/record

	// 端点路径：代理只认这四个，其余路径返回 fallback HTML。
	EndpointTCP   = "/v3/tcp"
	EndpointUDP   = "/v3/udp"
	EndpointICMP  = "/v3/icmp"
	EndpointProbe = "/v3/probe"

	// TUN 设备名的唯一来源：client/tun.New 与 util.IsTunIface 都必须引用，后者靠它识别
	// easyss 的 TUN 设备，使直连拨号器永不绑定到它。
	DefaultTunDeviceName       = "tun-easyss"
	DefaultTunDeviceNameDarwin = "utun9"
)
