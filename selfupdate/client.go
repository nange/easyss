package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const userAgent = "easyss-selfupdate"

// httpStatusError 表示获取请求返回了非 200 状态码。调用方可据此区分特定状态
// （例如 404 表示指定 tag 的 release 不存在）。
type httpStatusError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("unexpected http status %d from %s: %s", e.StatusCode, e.URL, e.Body)
}

// Client 优先通过本地 easyss HTTP 代理获取发布数据，代理失败时回退到直连。
type Client struct {
	proxy  *http.Client
	direct *http.Client
}

// NewClient 构建一个获取客户端；localHTTPPort <= 0 时禁用代理路径。
func NewClient(localHTTPPort int) *Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	newTransport := func(proxyFn func(*http.Request) (*url.URL, error)) *http.Transport {
		return &http.Transport{
			Proxy:                 proxyFn,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			// 空闲连接必须有回收上限：客户端是长驻的托盘进程，而本地 HTTP 代理
			// 侧没有 IdleTimeout，零值会让每次检查都永久占住一条 keep-alive
			// 连接——连同它背后的隧道流与两个 goroutine（见 Client.Close）。
			IdleConnTimeout: 30 * time.Second,
		}
	}

	c := &Client{
		direct: &http.Client{Transport: newTransport(http.ProxyFromEnvironment)},
	}
	if localHTTPPort > 0 {
		proxyURL := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(localHTTPPort)),
		}
		c.proxy = &http.Client{Transport: newTransport(http.ProxyURL(proxyURL))}
	}
	return c
}

// Close 释放两个 http.Client 的空闲连接。Client 不持有其它需要释放的资源，
// 但长驻进程（托盘）每次检查都会新建一个 Client，因此调用方必须关闭它：
// 否则空闲连接会一直占着本地代理的一条隧道流。
func (c *Client) Close() {
	if c == nil {
		return
	}
	if c.proxy != nil {
		c.proxy.CloseIdleConnections()
	}
	if c.direct != nil {
		c.direct.CloseIdleConnections()
	}
}

// Get 发起 GET 请求，先尝试本地代理，再尝试直连，并返回第一个成功的响应。
// 调用方必须关闭响应体。extraHeaders 会应用于每一次尝试。
func (c *Client) Get(ctx context.Context, rawURL string, extraHeaders map[string]string) (*http.Response, error) {
	clients := make([]*http.Client, 0, 2)
	if c.proxy != nil {
		clients = append(clients, c.proxy)
	}
	clients = append(clients, c.direct)

	var lastErr error
	for _, hc := range clients {
		resp, err := doRequest(hc, ctx, rawURL, extraHeaders)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func doRequest(hc *http.Client, ctx context.Context, rawURL string, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := hc.Do(req) //nolint:gosec // 请求 URL 来自我们自己的 release API 响应
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, &httpStatusError{
			StatusCode: resp.StatusCode,
			URL:        rawURL,
			Body:       string(body),
		}
	}
	return resp, nil
}
