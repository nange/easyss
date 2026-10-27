//go:build windows

package tunhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/protocol"
)

// 与主进程 client/proxy 的 /icmp/* 端点共享的 JSON 形状。字段名改动必须同时改
// client/proxy/http_proxy.go 的请求/响应类型。
type helperICMPClassifyRequest struct {
	Dst string `json:"dst"`
}

type helperICMPClassifyResponse struct {
	Action string `json:"action"`
}

type helperICMPProxyRequest struct {
	Dst     string `json:"dst"`
	Payload []byte `json:"payload"`
}

type helperICMPProxyResponse struct {
	Payload []byte `json:"payload"`
}

// httpICMPBackend 让 helper 里的 ICMPHandler 复用主进程的 router 与 StreamHandler：
// 分类走 /icmp/classify（同步、只需几毫秒），真正的代理走 /icmp/proxy（异步 goroutine）。
type httpICMPBackend struct {
	baseURL        string
	classifyClient *http.Client
	proxyClient    *http.Client
}

func newHTTPICMPBackend(httpAddr string) *httpICMPBackend {
	return &httpICMPBackend{
		baseURL:        "http://" + httpAddr,
		classifyClient: &http.Client{Timeout: 2 * time.Second},
		proxyClient:    &http.Client{},
	}
}

func (b *httpICMPBackend) Classify(dst string) (tun.ICMPAction, error) {
	body, err := json.Marshal(helperICMPClassifyRequest{Dst: dst})
	if err != nil {
		return tun.ICMPActionDirect, err
	}

	resp, err := b.classifyClient.Post(b.baseURL+"/icmp/classify", "application/json", bytes.NewReader(body))
	if err != nil {
		return tun.ICMPActionDirect, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return tun.ICMPActionDirect, fmt.Errorf("icmp classify: status %d", resp.StatusCode)
	}

	var out helperICMPClassifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return tun.ICMPActionDirect, fmt.Errorf("decode icmp classify: %w", err)
	}

	switch out.Action {
	case "block":
		return tun.ICMPActionBlock, nil
	case "direct":
		return tun.ICMPActionDirect, nil
	default:
		return tun.ICMPActionProxy, nil
	}
}

func (b *httpICMPBackend) OpenICMPStream(ctx context.Context, target string, echoPayload []byte, _ protocol.Method) ([]byte, error) {
	body, err := json.Marshal(helperICMPProxyRequest{Dst: target, Payload: echoPayload})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/icmp/proxy", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.proxyClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("icmp proxy: status %d", resp.StatusCode)
	}

	var out helperICMPProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode icmp proxy: %w", err)
	}
	return out.Payload, nil
}
