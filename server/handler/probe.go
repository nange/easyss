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

// ProbeHandler 提供预生成的随机载荷供客户端测量下载吞吐量。有效请求必须在 x-es 头
// 携带主密钥派生的能力令牌（与代理握手 salt 同名同格式）；其他请求得到伪装回退页。
type ProbeHandler struct {
	payload  []byte
	token    []byte
	limiter  *ipRateLimiter
	fallback *Fallback
}

// 载荷在服务器启动时生成后复用；fallback 为 nil 时回落到包级内置回退实例。
func NewProbeHandler(masterKey, payload []byte, fallback *Fallback) (*ProbeHandler, error) {
	tokenB64, err := crypto.ProbeToken(masterKey)
	if err != nil {
		return nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, err
	}
	return &ProbeHandler{
		payload:  payload,
		token:    token,
		limiter:  newIPRateLimiter(),
		fallback: fallback,
	}, nil
}

// fallbackFor 返回本 handler 使用的回退实例，未注入时回落到包级内置实例。
func (h *ProbeHandler) fallbackFor() *Fallback {
	if h.fallback != nil {
		return h.fallback
	}
	return builtinFallback()
}

// serveFallback 向响应写出一张伪装回退页面。
func (h *ProbeHandler) serveFallback(w http.ResponseWriter, r *http.Request) {
	h.fallbackFor().Serve(w, r)
}

func (h *ProbeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.ProtoAtLeast(2, 0) {
		h.serveFallback(w, r)
		return
	}

	tokenB64 := r.Header.Get("x-es")
	if tokenB64 == "" {
		h.serveFallback(w, r)
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil || len(token) != len(h.token) ||
		subtle.ConstantTimeCompare(token, h.token) != 1 {
		h.serveFallback(w, r)
		return
	}

	// 只对通过令牌校验的请求按源 IP 限速，令牌错误的请求早已得到廉价的回退页。
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
