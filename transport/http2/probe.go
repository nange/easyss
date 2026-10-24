package http2

import (
	"context"
	"net/http"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
)

// probeVerdict 归类单次探测的结果。
type probeVerdict int

const (
	// probeInconclusive：首个响应体字节前失败（RoundTrip 错误或非 200），不产生结论。
	probeInconclusive probeVerdict = iota
	// probeFast：载荷以不低于降级吞吐量阈值的速度送达。
	probeFast
	// probeSlow：探测超时内没有字节到达、服务端提前截断载荷，或响应体吞吐量低于降级阈值。
	probeSlow
	// probeUnsupported：服务端返回 200 但不是探测载荷，即不提供 /v3/probe。
	probeUnsupported
)

// maxProbeSpeed 是单次探测回报速度的上限：首块与流结束几乎同时时，微秒级 elapsed 会算出
// 荒谬的大数。
const maxProbeSpeed = 1 << 30 // 1GB/s

// slotProber 下载服务端预生成的随机载荷测量吞吐量。MaxConnsPerHost=1 把池固定在那一条
// 连接上，因此探测字节恰好经过被测连接。
type slotProber struct {
	serverURL   string
	token       string
	payloadSize int64
	// slowRTT 是所属传输层的慢路径 RTT 日志限流器，nil 表示不限流。
	slowRTT *slowRTTLogLimiter
}

// alive 在指定那一代连接上发起 HEAD /v3/probe，用一个 RTT 回答这条连接还能不能往返。拿到任何
// 响应（含 429、fallback 页面）都算活着，只有 RoundTrip 报错才判死；这一代已无连接时返回 ok=false。
func (p *slotProber) alive(ctx context.Context, gen *slotTransport) (alive, ok bool) {
	if gen == nil || gen.conn.Load() == nil {
		return false, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, p.serverURL+config.EndpointProbe, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("x-es", p.token)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", chromeUserAgent())

	resp, err := gen.tr.RoundTrip(req)
	if err != nil {
		// MaxConnsPerHost=1 使探测排在这一代占用的连接之后，而不是偷偷拨一条新连接。
		return false, true
	}
	_ = resp.Body.Close()
	return true, true
}

// probe 下载探测载荷并报告响应体吞吐量（不含 TTFB），结论按绝对降级阈值给出。
func (p *slotProber) probe(ctx context.Context, slot *transportSlot) (float64, probeVerdict) {
	probeCtx, cancel := context.WithTimeout(ctx, config.ProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, p.serverURL+config.EndpointProbe, nil)
	if err != nil {
		return 0, probeInconclusive
	}
	req.Header.Set("x-es", p.token)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", chromeUserAgent())

	// 与 alive 同一条不变量：这一代已无连接时不得白拨一条——那会得出关于另一条连接的
	// 吞吐结论，连接还会滞留在无人引用的池里。
	gen := slot.generation()
	if gen == nil || gen.conn.Load() == nil {
		return 0, probeInconclusive
	}

	// 必须在发起请求之前打点：客户端读循环与 RoundTrip 是并发的，连接上还有别的流时载荷
	// 可能已被缓冲进管道，把基准放在 RoundTrip 之后只会量到微秒级的取块时间。
	ttfbStart := time.Now()
	resp, err := gen.tr.RoundTrip(req)
	if err != nil {
		return 0, probeInconclusive
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, probeInconclusive
	}
	if resp.ContentLength != p.payloadSize ||
		resp.Header.Get("Content-Type") != "application/octet-stream" {
		// 200 但不是探测载荷（例如回落到 fallback HTML 页面）。
		return 0, probeUnsupported
	}

	buf := make([]byte, 32*1024)
	var total int64
	var start time.Time
	timed := false
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if !timed {
				timed = true
				start = time.Now()
				// 服务端在拨号源端之前就已提交响应，因此这是纯路径 RTT。越界样本
				// 标上与请求不同的来源，否则会与真正慢的请求混为一谈。
				d := time.Since(ttfbStart)
				stats.RecordRTT(d)
				p.slowRTT.log(d, slowRTTSample{
					source:   slowRTTSourceProbe,
					endpoint: config.EndpointProbe,
					slot:     slot,
				})
			}
		}
		if rErr != nil {
			break // EOF、超时或 RST 都算结束，是否送达完整由长度判定
		}
	}

	if total < p.payloadSize && probeCtx.Err() == nil {
		// 服务端提前结束这条流（截断/RST）：按已到达字节算出的吞吐不可比，一律记慢。
		return 0, probeSlow
	}

	var speed float64 = maxProbeSpeed
	if elapsed := time.Since(start); elapsed > 0 {
		speed = float64(total) / elapsed.Seconds()
		if speed > maxProbeSpeed {
			speed = maxProbeSpeed
		}
	}
	if speed < float64(config.DegradedThroughputThreshold) {
		return speed, probeSlow
	}
	return speed, probeFast
}
