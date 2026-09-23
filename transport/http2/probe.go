package http2

import (
	"context"
	"errors"
	"net/http"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
)

// errProbeNotConfirmed 归类未能确认槽位连接的探测：RoundTrip 失败（拨号/TLS/
// 流错误，或响应头到达前探测超时）或非 200 的拒绝（例如 429 限流）。预热会
// 用其未能预热的池名包裹它；生命周期则把同样的结论当作"状态不变"处理。
var errProbeNotConfirmed = errors.New("probe did not confirm the connection")

// probeVerdict 归类单次探测的结果。
type probeVerdict int

const (
	// probeInconclusive：探测在任一响应体字节到达前失败（RoundTrip 错误、
	// 非 200 状态）：连接要么已死（由流错误/轮换处理），要么被临时性拒绝
	// （429），因此不产生结论。
	probeInconclusive probeVerdict = iota
	// probeFast：载荷以不低于降级吞吐量阈值的速度送达。
	probeFast
	// probeSlow：探测超时内没有字节到达，或响应体吞吐量低于降级阈值。
	probeSlow
	// probeUnsupported：服务端返回 200 但不是探测载荷（Content-Type/
	// Content-Length 不符），即它不提供 /v3/probe 端点，客户端必须回退到
	// 被动检测。
	probeUnsupported
)

// maxProbeSpeed 对测量到的吞吐量设上限，使单次瞬时（elapsed==0）探测无法把
// 链路参考速度锁定到一个荒谬的值。
const maxProbeSpeed = 1 << 30 // 1GB/s

// slotProber 通过槽位的 http.Transport 下载服务端预生成的随机载荷，主动测量
// 某个槽位自身连接的下载吞吐量（MaxConnsPerHost=1 把 transport 固定到那一条
// 连接上，因此探测字节恰好经过被测连接）。
type slotProber struct {
	serverURL   string
	token       string
	payloadSize int64
}

// alive 在同一槽位的连接上发起一次 HEAD /v3/probe，用一个 RTT 回答"这条连接
// 还能不能往返"（见 transport.ConnLiveness）。它复用探测端点与能力令牌，但
// 不下载载荷：net/http 服务端对 HEAD 会丢弃响应体，因此开销只有一个 RTT。
// 判活标准与探测的吞吐量结论无关——拿到任何响应（200、429 限流、fallback
// 页面）都证明连接是活的；只有 RoundTrip 报错或超时才判死。
// 返回的 ok=false 表示"无法判定"（未配置探测令牌），调用方应按判死处理。
func (p *slotProber) alive(ctx context.Context, slot *transportSlot) (alive, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, p.serverURL+sharedconfig.EndpointProbe, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("x-es", p.token)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", chromeUserAgent())

	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		// 不可往返：连接已死（黑洞、接口消失、连接被关闭）。MaxConnsPerHost=1
		// 使这次探测排在本流仍在占用的那条连接之后，而不是偷偷拨一条新连接。
		return false, true
	}
	_ = resp.Body.Close()
	return true, true
}

// probe 通过槽位连接下载探测载荷并报告响应体吞吐量（不含 TTFB：计时从第一个
// 响应体分块开始）。结论依据绝对的降级阈值判定；生命周期在此基础上再应用
// 链路参考值的细化。
func (p *slotProber) probe(ctx context.Context, slot *transportSlot) (float64, probeVerdict) {
	probeCtx, cancel := context.WithTimeout(ctx, sharedconfig.ProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, p.serverURL+sharedconfig.EndpointProbe, nil)
	if err != nil {
		return 0, probeInconclusive
	}
	req.Header.Set("x-es", p.token)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", chromeUserAgent())

	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		// RoundTrip 失败（拨号/TLS/流错误，或响应头到达前超时）：连接已死或
		// 服务端不可达——不产生结论，这些情况由流错误和轮换处理。RoundTrip
		// 内部的健康重拨能完成请求，因此新连接绝不会被误判为慢。
		return 0, probeInconclusive
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// 拒绝（例如 429 限流）：是临时性的，稍后重新探测。
		return 0, probeInconclusive
	}
	if resp.ContentLength != p.payloadSize ||
		resp.Header.Get("Content-Type") != "application/octet-stream" {
		// 服务端返回 200 但不是探测载荷（例如来自不支持 /v3/probe 的服务器的
		// fallback HTML 页面）。
		return 0, probeUnsupported
	}

	buf := make([]byte, 32*1024)
	var total int64
	var start time.Time
	timed := false
	ttfbStart := time.Now()
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			if !timed {
				timed = true
				start = time.Now()
				// 响应头已到达，且服务端会立即写入载荷（不涉及源端），因此到
				// 第一个响应体分块的时间就是纯路径 RTT——与每次请求的 bootstrap
				// 往返采用相同的测量基准。
				stats.RecordRTT(time.Since(ttfbStart))
			}
		}
		if rErr != nil {
			break // EOF、超时或连接错误：按已到达的字节数计量
		}
	}

	if total == 0 {
		// 探测超时内没有任何字节到达（或响应体立即被截断）：在任何正常的
		// 链路上，128KB 的首批字节都远在 3 秒内到达，因此把它当作慢的证据。
		return 0, probeSlow
	}

	var speed float64 = maxProbeSpeed
	if elapsed := time.Since(start); elapsed > 0 {
		speed = float64(total) / elapsed.Seconds()
		if speed > maxProbeSpeed {
			speed = maxProbeSpeed
		}
	}
	if speed < float64(sharedconfig.DegradedThroughputThreshold) {
		return speed, probeSlow
	}
	return speed, probeFast
}
