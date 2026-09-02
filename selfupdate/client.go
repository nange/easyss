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

// Client fetches release data over the local easyss HTTP proxy first and
// falls back to a direct connection when the proxy fails.
type Client struct {
	proxy  *http.Client
	direct *http.Client
}

// NewClient builds a fetch client; localHTTPPort <= 0 disables the proxy path.
func NewClient(localHTTPPort int) *Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	newTransport := func(proxyFn func(*http.Request) (*url.URL, error)) *http.Transport {
		return &http.Transport{
			Proxy:                 proxyFn,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
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

// Get issues a GET request, trying the local proxy first and then the
// direct connection, and returns the first successful response. The caller
// must close the response body. extraHeaders are applied to every attempt.
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

	resp, err := hc.Do(req) //nolint:gosec // request URL comes from our own release API response
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected http status %d from %s: %s", resp.StatusCode, rawURL, string(body))
	}
	return resp, nil
}
