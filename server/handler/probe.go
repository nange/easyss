package handler

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// probeChunkSize 是 probe 载荷的写入粒度：每个块都会 flush，
// 使载荷以真实的网络速度到达客户端，而不是在服务端被缓冲。
const probeChunkSize = 32 * 1024

// ProbeHandler 提供预先生成的随机载荷，供客户端主动测量自身连接的下载吞吐量。
// 有效请求必须在 x-es 头中携带由主密钥派生的能力令牌（与代理握手的 salt
// 使用相同的头名称和线上格式）；其他任何请求都会得到伪装回退页面，
// 使服务器与真实网站无法区分。
type ProbeHandler struct {
	payload []byte
	token   []byte
	limiter *ipRateLimiter
}

// NewProbeHandler 构建 /v3/probe handler。载荷必须在服务器启动时生成；
// 复用同一个缓冲区使该端点开销极低且不可缓存（Cache-Control: no-store）。
func NewProbeHandler(masterKey, payload []byte) (*ProbeHandler, error) {
	tokenB64, err := crypto.ProbeToken(masterKey)
	if err != nil {
		return nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, err
	}
	return &ProbeHandler{
		payload: payload,
		token:   token,
		limiter: newIPRateLimiter(),
	}, nil
}

func (h *ProbeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.ProtoAtLeast(2, 0) {
		ServeFallback(w, r)
		return
	}

	tokenB64 := r.Header.Get("x-es")
	if tokenB64 == "" {
		ServeFallback(w, r)
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil || len(token) != len(h.token) ||
		subtle.ConstantTimeCompare(token, h.token) != 1 {
		ServeFallback(w, r)
		return
	}

	// 按源 IP 限制 probe 下载；token 错误的请求永远不会到达这里
	// （它们会得到廉价的回退页面）。
	if !h.limiter.Allow(clientIP(r)) {
		log.Error("[SERVER] probe rate limited", "remote", r.RemoteAddr)
		serveReject(w, http.StatusTooManyRequests)
		return
	}

	stats.RecordServerProbe()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.payload)))
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	_ = rc.Flush()

	for off := 0; off < len(h.payload); off += probeChunkSize {
		end := min(off+probeChunkSize, len(h.payload))
		if _, err := w.Write(h.payload[off:end]); err != nil {
			return
		}
		_ = rc.Flush()
	}
}
