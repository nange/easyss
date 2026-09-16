package main_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/txthinking/socks5"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	server "github.com/nange/easyss/v3/server"
	serverconfig "github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/shaper"
)

const (
	CACert = `-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIULPyfQyUssIDTxsGLzQJx6w5rbukwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAeFw0yNDAyMTgwNzA1MDBaFw0yOTAy
MTYwNzA1MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZWFzeS1jYS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT71NO1p1yANOG7AkEe1bQvcQp6fNgRRqvwrC/cIGp6bDqt
H3klE8D22g5upORqkETrqlKeqi0UxflAUD9RSh7Ro0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU8pqT0wmFdRQ6gxX+ZWAWhMon
fIQwCgYIKoZIzj0EAwIDSAAwRQIhAO3ZLMAh8nlR2cJbecUZJ51GbBbLny5CdcN7
CbTHmkaiAiB+LABnNKD+O0P+UPidt+nBpo+2u1/W7wtQvKJcFVl+mQ==
-----END CERTIFICATE-----
`
	ServerCert = `-----BEGIN CERTIFICATE-----
MIICIDCCAcagAwIBAgIUPMWIWsDwAl4fIpDSHDbPAS/YX2MwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAgFw0yNDAyMTgwNzA3MDBaGA8yMTI0
MDEyNTA3MDcwMFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRgwFgYDVQQDEw9lYXN5LXNlcnZlci5uZXQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATaBuIN8NmDmSMmSpXbNp2pzqIjTtyvccgEGTdx
TbtWF2YvqqwmQY/fPDyRDp1hCq2toD1wCEjCXOJx5BaF1n8Wo4GHMIGEMA4GA1Ud
DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBSnOwxAIjDEYPp88Ooed4HWL9r8bTAfBgNVHSMEGDAWgBTympPTCYV1
FDqDFf5lYBaEyid8hDAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMCA0gAMEUC
IGphTgfgOgRRGIqDX/ByZx33QUh6P+nRSPyMPLV24nDGAiEAl0I45LBWXopCzDLD
ftJgQof/GMr8+pMLn0UM/Xv5xec=
-----END CERTIFICATE-----
`
	ServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO8NZoPnbSD3NL9PmL9zMz/OUvFuwYVGzzicctyWbf57oAoGCCqGSM49
AwEHoUQDQgAE2gbiDfDZg5kjJkqV2zadqc6iI07cr3HIBBk3cU27VhdmL6qsJkGP
3zw8kQ6dYQqtraA9cAhIwlziceQWhdZ/Fg==
-----END EC PRIVATE KEY-----
`
)

const (
	testServerAddr = "127.0.0.1"
	testPassword   = "test-pass"

	// readinessTimeout 限制测试框架等待异步启动的服务器接受连接的时间。
	// 启动失败会立即通过 error channel 上报，因此该值只需覆盖高负载下的
	// 调度延迟（实测：普通构建约 0.2s，-race 下约 0.7s）。
	readinessTimeout = 15 * time.Second
)

// testExternalURLs 用于测试完整的代理隧道。
// 提供多个 URL，以便在某个暂时不可用时进行回退。
var testExternalURLs = []string{
	"http://www.example.com",
	"https://www.baidu.com",
	"http://httpbin.org/get",
}

// fetchExternalURL 通过 client 尝试 GET 各个 URL，并在多个回退 URL 之间重试
func fetchExternalURL(t *testing.T, client *http.Client) (body []byte, status int) {
	t.Helper()
	for _, url := range testExternalURLs {
		for attempt := range 2 {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err := client.Get(url)
			if err != nil {
				t.Logf("GET %s attempt %d: %v", url, attempt+1, err)
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close() //nolint:errcheck
			if err != nil {
				t.Logf("read body %s attempt %d: %v", url, attempt+1, err)
				continue
			}
			if resp.StatusCode == http.StatusOK {
				return body, resp.StatusCode
			}
			t.Logf("GET %s attempt %d: status=%d body=%d bytes", url, attempt+1, resp.StatusCode, len(body))
		}
	}
	t.Fatal("all external URLs failed")
	return nil, 0
}

// loopbackAddr 为指定端口格式化一个 127.0.0.1 地址。
func loopbackAddr(port int) string {
	return testServerAddr + ":" + strconv.Itoa(port)
}

// freeTCPPort 返回一个当前空闲的 loopback TCP 端口。每个测试单独选端口，
// 可以避免本包的并发运行（另一个终端、IDE 测试运行、另一个检出目录）
// 互相抢占对方的监听端口。
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// freeSocks5Port 返回一个在 TCP 和 UDP 上都空闲的 loopback 端口：
// txthinking/socks5 服务器会在同一地址上同时绑定 TCP 监听器和 UDP socket，
// 因此仅 TCP 空闲的端口仍然无法启动。
func freeSocks5Port(t *testing.T) int {
	t.Helper()
	for range 20 {
		port := freeTCPPort(t)
		pc, err := net.ListenPacket("udp", loopbackAddr(port))
		if err != nil {
			continue
		}
		require.NoError(t, pc.Close())
		return port
	}
	t.Fatal("no loopback port free on both tcp and udp")
	return 0
}

// waitForReady 轮询 addr 直到其接受 TCP 连接，确保测试框架只在异步启动的
// 服务器真正开始监听后才继续。startErr 上发布的启动失败会立即以该错误中止：
// 否则等待超时会把 "address already in use"（或任何其他启动失败）伪装成普通的
// 就绪超时，甚至会把占用端口的其他进程误认为是被测服务器。
func waitForReady(what, addr string, startErr <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		select {
		case err := <-startErr:
			return fmt.Errorf("%s (%s) failed to start: %w", what, addr, err)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("%s (%s) did not accept connections within %s: %w", what, addr, timeout, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startLocalTargetServer 启动一个用于测试直连/本地连接的基础 HTTP 服务器。
// 它返回内核选择的监听地址以及用于关闭服务器的 cleanup 函数。监听器在此处
// 绑定而不是在 Serve 内部绑定，因此端口被占用时测试会立即失败，且地址可用
// 之前无需任何轮询。
func startLocalTargetServer(t *testing.T) (string, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "hello-from-target: %s", r.URL.Path) //nolint:errcheck
	})

	lis, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(lis)
	}()

	return lis.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	}
}

// startTCPEchoServer 启动一个用于 CloseWrite 测试的 TCP echo 服务器。
// 与目标服务器一样，它绑定自己的临时端口并返回该端口。
func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 1024)
				for {
					nr, err := c.Read(buf)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
					if _, err := c.Write(buf[:nr]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return lis.Addr().String(), func() { _ = lis.Close() }
}

type testHarness struct {
	tempDir  string
	certPath string
	keyPath  string
	caPath   string

	serverAddr string
	socksAddr  string
	httpAddr   string
	targetAddr string
	echoAddr   string

	cli *client.Client

	// closers 按启动顺序保存每个已启动组件的清理函数；Close 按相反顺序执行。
	// socks5 代理只有在 Start 报告成功之后才会被追加：txthinking/socks5
	// 会在绑定同一地址的 UDP socket 之前注册 TCP runner，因此一旦 Start
	// 返回错误，其 Shutdown 会因 runner 组永不关闭的 done channel 而永久阻塞。
	closers []func()

	cleanupOnce sync.Once
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{}

	// 每个监听器都使用内核选择的端口：同一台机器上本包的两个运行实例
	// 不能互相争抢监听端口，且端口被占用时必须明显失败，而不是被误认为
	// 仅仅是启动缓慢。
	serverPort := freeTCPPort(t)
	socksPort := freeSocks5Port(t)
	httpPort := freeTCPPort(t)
	h.serverAddr = loopbackAddr(serverPort)
	h.socksAddr = loopbackAddr(socksPort)
	h.httpAddr = loopbackAddr(httpPort)

	// 写入证书文件
	h.tempDir = t.TempDir()
	h.certPath = filepath.Join(h.tempDir, "cert.pem")
	h.keyPath = filepath.Join(h.tempDir, "key.pem")
	h.caPath = filepath.Join(h.tempDir, "ca.pem")

	require.NoError(t, os.WriteFile(h.certPath, []byte(ServerCert), 0644))
	require.NoError(t, os.WriteFile(h.keyPath, []byte(ServerKey), 0644))
	require.NoError(t, os.WriteFile(h.caPath, []byte(CACert), 0644))

	// 启动本地目标服务器
	targetAddr, targetCleanup := startLocalTargetServer(t)
	t.Cleanup(targetCleanup)
	h.targetAddr = targetAddr

	echoAddr, echoCleanup := startTCPEchoServer(t)
	t.Cleanup(echoCleanup)
	h.echoAddr = echoAddr

	// 注册在本地目标之后，因此会先于它们的 cleanup 执行（t.Cleanup 是
	// LIFO）：即使 t.Fatal 在未运行 defer 的情况下展开测试，下面启动的
	// 每个组件也都会自行清理。
	t.Cleanup(h.Close)

	// 创建服务器配置
	serverCfg := &serverconfig.FileConfig{
		Timeout: 30,
		Server: serverconfig.ServerConfig{
			Listen:   h.serverAddr,
			Password: testPassword,
			CertPath: h.certPath,
			KeyPath:  h.keyPath,
		},
	}

	srv, err := server.New(serverCfg)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()
	h.closers = append(h.closers, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	})
	require.NoError(t, waitForReady("v3 server", h.serverAddr, serverErr, readinessTimeout))

	// 创建客户端配置
	clientCfg := &clientconfig.ClientConfig{
		ConfigVersion: 3,
		Servers: []*clientconfig.ServerProfile{
			{
				Address:  testServerAddr,
				Port:     serverPort,
				Password: testPassword,
				Method:   "aes-256-gcm",
				SNI:      testServerAddr,
				CAPath:   h.caPath,
				Default:  true,
			},
		},
		Local: clientconfig.LocalConfig{
			SocksPort: socksPort,
			HTTPPort:  httpPort,
		},
		Routing: clientconfig.RoutingConfig{
			ProxyRule: "proxy",
			IPV6Rule:  "disable",
		},
		Transport: clientconfig.TransportConfig{
			Protocol:     "h2",
			ConnCountMax: 4,
		},
		Shaper: clientconfig.ShaperConfig{
			BatchWindowMS: 3,
		},
		Log: clientconfig.LogConfig{
			Level: "warn",
		},
		Timeout: 30,
	}

	cli, err := client.New(clientCfg)
	require.NoError(t, err)
	h.cli = cli
	h.closers = append(h.closers, func() { _ = cli.Close() })

	// 确定加密方法
	method := protocol.MethodFromString("aes-256-gcm")

	// 创建 StreamHandler
	timeouts := sharedconfig.NewTimeouts(clientCfg.TimeoutDuration())
	shaperCfg := shaper.Config{
		BatchWindowMS: clientCfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: clientCfg.Shaper.CoverBudgetRatio,
		},
	}
	handler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, timeouts.StreamIdle)

	// 启动 SOCKS5 代理
	socksServer, err := proxy.NewSocks5Server(proxy.Socks5Options{
		ListenAddr:        h.socksAddr,
		Handler:           handler,
		Router:            cli.Router(),
		Method:            method,
		DisableQUIC:       true,
		Timeouts:          timeouts,
		DirectDialContext: cli.DialContext,
	})
	require.NoError(t, err)

	socksErr := make(chan error, 1)
	go func() {
		socksErr <- socksServer.Start()
	}()
	require.NoError(t, waitForReady("socks5 proxy", h.socksAddr, socksErr, readinessTimeout))
	// 只有现在才追加：在 socks5 内部失败的 Start 会留下一个 Shutdown 永远
	// 无法完成的 runner 组（参见 closers 字段的注释）。
	h.closers = append(h.closers, func() { _ = socksServer.Close() })

	// 启动 HTTP 代理
	httpProxy, err := proxy.NewHTTPProxyServer(proxy.HTTPProxyOptions{
		ListenAddr: h.httpAddr,
		SocksAddr:  h.socksAddr,
		Timeout:    timeouts.Base,
		Handler:    handler,
		Router:     cli.Router(),
		Method:     method,
		Dial:       cli.DialContext,
	})
	require.NoError(t, err)

	httpErr := make(chan error, 1)
	go func() {
		httpErr <- httpProxy.Start()
	}()
	h.closers = append(h.closers, func() { _ = httpProxy.Close() })
	require.NoError(t, waitForReady("http proxy", h.httpAddr, httpErr, readinessTimeout))

	return h
}

func (h *testHarness) Close() {
	h.cleanupOnce.Do(func() {
		// 按启动顺序的逆序执行：先代理，再客户端，最后是客户端所连接的服务器。
		for _, closer := range slices.Backward(h.closers) {
			closer()
		}
	})
}

// TestV3Integration_Socks5Proxy 测试通过 v3 隧道经 SOCKS5 代理发起 HTTP 请求
func TestV3Integration_Socks5Proxy(t *testing.T) {
	h := newTestHarness(t)

	sc, err := socks5.NewClient(h.socksAddr, "", "", 0, 0)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := sc.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				_ = conn.SetDeadline(time.Time{})
				return conn, nil
			},
			TLSHandshakeTimeout: 30 * time.Second,
			MaxConnsPerHost:     1,
		},
		Timeout: 60 * time.Second,
	}

	body, status := fetchExternalURL(t, client)
	assert.Equal(t, http.StatusOK, status)
	assert.Greater(t, len(body), 100)
	t.Logf("SOCKS5 proxy response: %d bytes", len(body))
}

// TestV3Integration_HTTPProxy 测试通过 v3 隧道经 HTTP 代理发起 HTTP 请求
func TestV3Integration_HTTPProxy(t *testing.T) {
	h := newTestHarness(t)

	proxyAddr := "http://" + h.httpAddr
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyAddr)
			},
			TLSHandshakeTimeout: 30 * time.Second,
			MaxConnsPerHost:     1,
		},
		Timeout: 60 * time.Second,
	}

	body, status := fetchExternalURL(t, client)
	assert.Equal(t, http.StatusOK, status)
	assert.Greater(t, len(body), 100)
	t.Logf("HTTP proxy response: %d bytes", len(body))
}

// TestV3Integration_LocalDirect 测试本地（LAN）连接走直连
func TestV3Integration_LocalDirect(t *testing.T) {
	h := newTestHarness(t)

	sc, err := socks5.NewClient(h.socksAddr, "", "", 0, 0)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := sc.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				_ = conn.SetDeadline(time.Time{})
				return conn, nil
			},
			MaxConnsPerHost: 1,
		},
		Timeout: 30 * time.Second,
	}

	targetURL := "http://" + h.targetAddr + "/direct-test"
	resp, err := client.Get(targetURL)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "hello-from-target: /direct-test")
}

// TestV3Integration_CloseWrite 测试通过 SOCKS5 代理进行 TCP 半关闭
func TestV3Integration_CloseWrite(t *testing.T) {
	h := newTestHarness(t)

	msg := "hello-closewrite"

	sc, err := socks5.NewClient(h.socksAddr, "", "", 30, 30)
	require.NoError(t, err)

	conn, err := sc.Dial("tcp", h.echoAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// 清除 SOCKS5 协商设置的任何 deadline
	_ = conn.SetDeadline(time.Time{})

	// socks5.Client 包装了真实的 TCP 连接；将其取出以执行 CloseWrite
	socksClient, ok := conn.(*socks5.Client)
	require.True(t, ok, "expected *socks5.Client from SOCKS5 dial")
	tcpConn, ok := socksClient.TCPConn.(*net.TCPConn)
	require.True(t, ok, "expected *net.TCPConn as underlying connection")

	// 发送消息
	_, err = tcpConn.Write([]byte(msg))
	require.NoError(t, err)

	// 关闭写侧（半关闭）
	err = tcpConn.CloseWrite()
	require.NoError(t, err)

	// 读取响应
	buf := make([]byte, 1024)
	nr, err := tcpConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:nr]))
}

// TestV3Integration_Router 测试 router 是否正确地对主机进行分类
func TestV3Integration_Router(t *testing.T) {
	h := newTestHarness(t)

	rt := h.cli.Router()

	// proxy_rule=proxy 时，所有非 LAN 主机都应走代理
	// LAN 主机无论何种规则都始终直连
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("localhost"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("baidu.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("example.com"))

	// 切换到 auto 规则
	rt.SetProxyRule(router.ProxyRuleAuto)

	// google.com 应走代理（国外站点）
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))

	// baidu.com 应直连（国内站点）
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("baidu.com"))

	// LAN 主机仍然直连
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
}

// TestV3Integration_ConfigDefaults 测试配置默认值是否正确生效
func TestV3Integration_ConfigDefaults(t *testing.T) {
	cfg := clientconfig.DefaultConfig()

	assert.Equal(t, 3, cfg.ConfigVersion)
	assert.Equal(t, 4080, cfg.Local.SocksPort)
	assert.Equal(t, 5080, cfg.Local.HTTPPort)
	assert.Equal(t, "auto", cfg.Routing.ProxyRule)
	assert.Equal(t, "auto", cfg.Routing.IPV6Rule)
	assert.Equal(t, 30, cfg.Timeout)
	assert.Equal(t, "info", cfg.Log.Level)

	// Clone 应产生等价的配置
	clone := cfg.Clone()
	assert.Equal(t, cfg.Local.SocksPort, clone.Local.SocksPort)

	// 未配置任何服务器时 DefaultServer 返回 nil
	assert.Nil(t, cfg.DefaultServer())
	assert.Equal(t, "", cfg.ServerURL())
}

// TestFreeSocks5PortIsFreeOnTCPAndUDP 固化了 socks5 端口不能用 freeTCPPort
// 选择的原因：txthinking/socks5 服务器会在同一地址上绑定 TCP 和 UDP，
// 因此仅 TCP 空闲的端口仍然无法启动。
func TestFreeSocks5PortIsFreeOnTCPAndUDP(t *testing.T) {
	port := freeSocks5Port(t)

	l, err := net.Listen("tcp", loopbackAddr(port))
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", loopbackAddr(port))
	require.NoError(t, err)

	require.NoError(t, pc.Close())
	require.NoError(t, l.Close())
}

// TestWaitForReadyReportsStartError 固化了快速失败契约：启动失败的服务器
// 必须以其真实错误上报，而不是伪装成就绪超时。
func TestWaitForReadyReportsStartError(t *testing.T) {
	addr := loopbackAddr(freeTCPPort(t))
	startErr := make(chan error, 1)
	startErr <- errors.New("listen udp " + addr + ": bind: address already in use")

	start := time.Now()
	err := waitForReady("socks5 proxy", addr, startErr, 30*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "socks5 proxy")
	assert.Contains(t, err.Error(), "bind: address already in use")
	assert.Less(t, time.Since(start), time.Second, "a start error must abort the wait immediately")
}

// TestWaitForReadyTimesOut 覆盖剩余的情况：没有任何监听且没有启动错误可上报。
func TestWaitForReadyTimesOut(t *testing.T) {
	addr := loopbackAddr(freeTCPPort(t))

	err := waitForReady("http proxy", addr, make(chan error), 300*time.Millisecond)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http proxy")
	assert.Contains(t, err.Error(), "did not accept connections")
}
