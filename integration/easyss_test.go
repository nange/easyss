package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
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
	xproxy "golang.org/x/net/proxy"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
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

	// 只覆盖高负载下的调度延迟：启动失败会立即通过 error channel 上报。
	readinessTimeout = 15 * time.Second
)

// 窗口刻意落在各平台动态端口段（Linux 32768+、macOS/Windows 49152+）之下，
// 减少与内核或其他进程自动分配的端口撞车。
const (
	socks5PortBase = 20000
	socks5PortSpan = 10000
)

var testExternalURLs = []string{
	"http://www.example.com",
	"https://www.baidu.com",
	"http://httpbin.org/get",
}

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

func loopbackAddr(port int) string {
	return testServerAddr + ":" + strconv.Itoa(port)
}

// portReservation 以保持监听的方式占住端口，直到真正的服务即将绑定它：
// 挑完就放会让并行跑的其他包抢走同一端口，端口撞车最终以莫名的 EOF 收场。
type portReservation struct {
	listener net.Listener
	packet   net.PacketConn // 仅 SOCKS5 预留需要：同一端口的 UDP 侧
}

func reserveTCPPort(t *testing.T) (int, *portReservation) {
	t.Helper()

	l, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)
	r := &portReservation{listener: l}
	// 兜底：正常路径在派发 Start 前同步 release，harness 中途失败时由 Cleanup 收尾。
	t.Cleanup(func() { r.release() })
	return l.Addr().(*net.TCPAddr).Port, r
}

// reserveSocks5Port 挑一个 TCP 与 UDP 两侧都空闲的端口：SOCKS5 入口会在同一地址上
// 绑定 TCP 监听器与 UDP 中继 socket，只占住 TCP 侧不足以保证它能启动。
func reserveSocks5Port(t *testing.T) (int, *portReservation) {
	t.Helper()

	return reserveSocks5PortAt(t, socks5PortBase+rand.IntN(socks5PortSpan))
}

// reserveSocks5PortAt 显式换端口逐个尝试，而不是反复用 ":0" 让内核挑：
// 内核会把刚释放的端口原样再发一次，某一侧恰好不可用的候选会让重试循环原地打转。
func reserveSocks5PortAt(t *testing.T, start int) (int, *portReservation) {
	t.Helper()

	var lastErr error
	for i := range socks5PortSpan {
		port := socks5PortBase + (start-socks5PortBase+i)%socks5PortSpan
		r, err := tryReserveSocks5Port(loopbackAddr(port))
		if err != nil {
			lastErr = err
			continue
		}
		t.Cleanup(func() { r.release() })
		return port, r
	}
	t.Fatalf("no loopback port free on both tcp and udp in [%d, %d), last error: %v",
		socks5PortBase, socks5PortBase+socks5PortSpan, lastErr)
	return 0, nil
}

// 任一侧不可用时返回错误且不留下已占用的 socket，由调用方换下一个候选端口。
func tryReserveSocks5Port(addr string) (*portReservation, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		// TCP 侧已经拿到手：这里必须自己关掉，否则失败分支会把刚释放的端口又占回去。
		_ = l.Close()
		return nil, err
	}
	return &portReservation{listener: l, packet: pc}, nil
}

// release 必须在派发 Start 的前一行调用；它是幂等的，可与 Cleanup 各调用一次。
func (r *portReservation) release() {
	if r.packet != nil {
		_ = r.packet.Close()
		r.packet = nil
	}
	if r.listener != nil {
		_ = r.listener.Close()
		r.listener = nil
	}
}

// waitForReady 只在服务器真正开始监听后才继续，startErr 上的启动失败立即中止
// （否则会伪装成就绪超时）。probe 非 nil 时还要求协议探测通过：端口撞车时拨号会被
// 占住该端口的邻居组件应答。
func waitForReady(what, addr string, startErr <-chan error, timeout time.Duration, probe func(net.Conn) bool) error {
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
			ready := true
			if probe != nil && !probe(conn) {
				ready = false
				lastErr = fmt.Errorf("connected but %s did not answer its protocol probe (port occupied by a foreign listener?)", what)
			}
			conn.Close() //nolint:errcheck
			if ready {
				return nil
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s (%s) did not accept connections within %s: %w", what, addr, timeout, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 只有 SOCKS5 服务器会以首字节 0x05 应答；端口撞车时接管的 v3 TLS 服务端会让探测超时。
func probeSocks5Greeting(conn net.Conn) bool {
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return reply[0] == 0x05
}

// 监听器在此处绑定而不是在 Serve 内部绑定，端口被占用时测试会立即失败，且无需轮询。
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

	// closers 按启动顺序保存清理函数，Close 按相反顺序执行。
	// socks5 代理只在 Start 报告成功后才追加：失败的 Start 会留下 Shutdown 永远无法完成的 runner 组。
	closers []func()

	cleanupOnce sync.Once
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{}

	// 端口以预留方式占住直到组件即将绑定：同一台机器上本包的其他运行实例不会互相争抢，
	// 端口被占用时必须明显失败，而不是被误认为启动缓慢。
	serverPort, serverRes := reserveTCPPort(t)
	socksPort, socksRes := reserveSocks5Port(t)
	httpPort, httpRes := reserveTCPPort(t)
	// 三份预留同时保持监听，内核不可能复用同一端口；断言是廉价的防线。
	require.True(t, serverPort != socksPort && serverPort != httpPort && socksPort != httpPort,
		fmt.Sprintf("harness ports collided: server=%d socks=%d http=%d", serverPort, socksPort, httpPort))
	h.serverAddr = loopbackAddr(serverPort)
	h.socksAddr = loopbackAddr(socksPort)
	h.httpAddr = loopbackAddr(httpPort)

	h.tempDir = t.TempDir()
	h.certPath = filepath.Join(h.tempDir, "cert.pem")
	h.keyPath = filepath.Join(h.tempDir, "key.pem")
	h.caPath = filepath.Join(h.tempDir, "ca.pem")

	require.NoError(t, os.WriteFile(h.certPath, []byte(ServerCert), 0644))
	require.NoError(t, os.WriteFile(h.keyPath, []byte(ServerKey), 0644))
	require.NoError(t, os.WriteFile(h.caPath, []byte(CACert), 0644))

	targetAddr, targetCleanup := startLocalTargetServer(t)
	t.Cleanup(targetCleanup)
	h.targetAddr = targetAddr

	echoAddr, echoCleanup := startTCPEchoServer(t)
	t.Cleanup(echoCleanup)
	h.echoAddr = echoAddr

	// 注册在本地目标之后，因此会先于它们的 cleanup 执行（t.Cleanup 是 LIFO）。
	t.Cleanup(h.Close)

	serverCfg := &serverconfig.FileConfig{
		Timeout: 30,
		Server: serverconfig.ServerConfig{
			Bind:     testServerAddr,
			Port:     serverPort,
			Password: testPassword,
			CertPath: h.certPath,
			KeyPath:  h.keyPath,
		},
	}

	srv, err := server.New(serverCfg)
	require.NoError(t, err)

	serverRes.release()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()
	h.closers = append(h.closers, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	})
	require.NoError(t, waitForReady("v3 server", h.serverAddr, serverErr, readinessTimeout, nil))

	clientCfg := &clientconfig.ClientConfig{
		ConfigVersion: 3,
		Servers: []*clientconfig.ServerProfile{
			{
				Host:     testServerAddr,
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
		Shaper: shaper.Config{
			BatchWindowMS: 3,
		},
		Log: log.Config{
			Level: "warn",
		},
		Timeout: 30,
	}

	cli, err := client.New(clientCfg)
	require.NoError(t, err)
	h.cli = cli
	h.closers = append(h.closers, func() { _ = cli.Close() })

	method := protocol.MethodFromString("aes-256-gcm")

	timeouts := config.NewTimeouts(clientCfg.TimeoutDuration())
	handler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), clientCfg.Shaper, timeouts)

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

	socksRes.release()
	socksErr := make(chan error, 1)
	go func() {
		socksErr <- socksServer.Start()
	}()
	require.NoError(t, waitForReady("socks5 proxy", h.socksAddr, socksErr, readinessTimeout, probeSocks5Greeting))
	// 只有现在才追加：在 socks5 内部失败的 Start 会留下 Shutdown 永远无法完成的 runner 组。
	h.closers = append(h.closers, func() { _ = socksServer.Close() })

	httpProxy, err := proxy.NewHTTPProxyServer(proxy.HTTPProxyOptions{
		ListenAddr: h.httpAddr,
		SocksAddr:  h.socksAddr,
		Timeouts:   timeouts,
		Handler:    handler,
		Router:     cli.Router(),
		Method:     method,
		Dial:       cli.DialContext,
	})
	require.NoError(t, err)

	httpRes.release()
	httpErr := make(chan error, 1)
	go func() {
		httpErr <- httpProxy.Start()
	}()
	h.closers = append(h.closers, func() { _ = httpProxy.Close() })
	require.NoError(t, waitForReady("http proxy", h.httpAddr, httpErr, readinessTimeout, nil))

	return h
}

func (h *testHarness) Close() {
	h.cleanupOnce.Do(func() {
		for _, closer := range slices.Backward(h.closers) {
			closer()
		}
	})
}

// x/net/proxy 的 SOCKS5 客户端不在协商成功后残留 deadline，调用方不必手工清理握手 deadline。
func socks5DialFunc(t *testing.T, socksAddr string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	require.NoError(t, err)
	cd, ok := d.(xproxy.ContextDialer)
	require.True(t, ok, "x/net/proxy SOCKS5 dialer must support contexts")
	return cd.DialContext
}

func TestV3Integration_Socks5Proxy(t *testing.T) {
	h := newTestHarness(t)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         socks5DialFunc(t, h.socksAddr),
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

func TestV3Integration_LocalDirect(t *testing.T) {
	h := newTestHarness(t)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     socks5DialFunc(t, h.socksAddr),
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

// 断言端到端行为：SOCKS5 入口返回的连接必须实现 CloseWrite，且半关闭要一路传播到目标，
// 反方向仍能继续传输。只断言具体连接类型、再手取底层 *net.TCPConn 会掩盖这一点。
func TestV3Integration_CloseWrite(t *testing.T) {
	h := newTestHarness(t)

	msg := "hello-closewrite"

	// 用裸 TCP + 手工握手：x/net/proxy 返回不透明的 *socks.Conn，拿不到底层 *net.TCPConn。
	conn := socks5HandshakeConnect(t, h.socksAddr, h.echoAddr)
	defer conn.Close() //nolint:errcheck

	_, err := conn.Write([]byte(msg))
	require.NoError(t, err)

	require.NoError(t, conn.CloseWrite())

	buf := make([]byte, 1024)
	nr, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:nr]))
}

func socks5HandshakeConnect(t *testing.T, socksAddr, target string) *net.TCPConn {
	t.Helper()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, greeting, "server must select no-auth")

	host, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	portNum, err := strconv.Atoi(port)
	require.NoError(t, err)
	require.LessOrEqual(t, len(host), 255)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(portNum>>8), byte(portNum))
	_, err = conn.Write(req)
	require.NoError(t, err)

	hdr := make([]byte, 4)
	_, err = io.ReadFull(conn, hdr)
	require.NoError(t, err)
	require.Equal(t, byte(0x05), hdr[0], "reply version")
	require.Equal(t, byte(0x00), hdr[1], "CONNECT must succeed")
	switch hdr[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 6))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 18))
	case 0x03:
		var ln [1]byte
		_, err = io.ReadFull(conn, ln[:])
		require.NoError(t, err)
		_, err = io.ReadFull(conn, make([]byte, int(ln[0])+2))
	default:
		t.Fatalf("unexpected bind atyp %d", hdr[3])
	}
	require.NoError(t, err)

	// 之后是纯数据通道，清掉握手期的 deadline。
	require.NoError(t, conn.SetDeadline(time.Time{}))
	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok, "dial to a local loopback listener must yield *net.TCPConn, got %T", conn)
	return tcp
}

func TestV3Integration_Router(t *testing.T) {
	h := newTestHarness(t)

	rt := h.cli.Router()

	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("localhost"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("baidu.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("example.com"))

	rt.SetProxyRule(router.ProxyRuleAuto)

	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))

	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("baidu.com"))

	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
}

func TestV3Integration_ConfigDefaults(t *testing.T) {
	// 走生产加载简化配置的同一条路径：BuildSimpleConfig 负责把 0 值归一化成默认端口、规则与超时。
	cfg, err := clientconfig.BuildSimpleConfig(&config.SimpleConfig{
		Server:    "example.com",
		Password:  "secret",
		LocalPort: config.DefaultSocksPort,
	})
	require.NoError(t, err)

	assert.Equal(t, 3, cfg.ConfigVersion)
	assert.Equal(t, 4080, cfg.Local.SocksPort)
	assert.Equal(t, 5080, cfg.Local.HTTPPort)
	assert.Equal(t, "auto", cfg.Routing.ProxyRule)
	assert.Equal(t, "auto", cfg.Routing.IPV6Rule)
	assert.Equal(t, 30, cfg.Timeout)
	assert.Equal(t, "info", cfg.Log.Level)

	clone := cfg.Clone()
	assert.Equal(t, cfg.Local.SocksPort, clone.Local.SocksPort)

	assert.Nil(t, (&clientconfig.ClientConfig{}).DefaultServer())
	assert.Equal(t, "", (&clientconfig.ClientConfig{}).ServerURL())
}

func TestReserveSocks5PortHoldsTCPAndUDP(t *testing.T) {
	port, r := reserveSocks5Port(t)
	t.Cleanup(func() { r.release() })

	_, err := net.Listen("tcp", loopbackAddr(port))
	require.Error(t, err, "reservation must hold the TCP side")
	_, err = net.ListenPacket("udp", loopbackAddr(port))
	require.Error(t, err, "reservation must hold the UDP side")

	r.release()

	l, err := net.Listen("tcp", loopbackAddr(port))
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", loopbackAddr(port))
	require.NoError(t, err)

	require.NoError(t, pc.Close())
	require.NoError(t, l.Close())
}

// 候选端口某一侧不可用时必须换下一个：Windows 上内核会把刚释放的端口再发一次，
// 依赖 ":0" 的重试循环会一直撞在同一个端口上。
func TestReserveSocks5PortSkipsBlockedCandidate(t *testing.T) {
	blocked, blockedPC := blockedSocks5Candidate(t)
	t.Cleanup(func() { _ = blockedPC.Close() })

	port, r := reserveSocks5PortAt(t, blocked)
	t.Cleanup(func() { r.release() })

	if port == blocked {
		t.Fatalf("scanner returned the blocked candidate %d", blocked)
	}
	if port < socks5PortBase || port >= socks5PortBase+socks5PortSpan {
		t.Errorf("scanner returned %d outside the candidate window [%d, %d)",
			port, socks5PortBase, socks5PortBase+socks5PortSpan)
	}
	_, err := net.Listen("tcp", loopbackAddr(port))
	require.Error(t, err, "returned port must be held on the tcp side")
	_, err = net.ListenPacket("udp", loopbackAddr(port))
	require.Error(t, err, "returned port must be held on the udp side")
}

func blockedSocks5Candidate(t *testing.T) (int, net.PacketConn) {
	t.Helper()

	start := rand.IntN(socks5PortSpan)
	for i := range 20 {
		port := socks5PortBase + (start+i)%socks5PortSpan
		pc, err := net.ListenPacket("udp", loopbackAddr(port))
		if err == nil {
			return port, pc
		}
	}
	t.Fatal("no candidate port with a free udp side in the scan window")
	return 0, nil
}

// 启动失败的服务器必须以其真实错误上报，而不是伪装成就绪超时。
func TestWaitForReadyReportsStartError(t *testing.T) {
	port, r := reserveTCPPort(t)
	t.Cleanup(func() { r.release() })
	addr := loopbackAddr(port)
	startErr := make(chan error, 1)
	startErr <- errors.New("listen udp " + addr + ": bind: address already in use")

	start := time.Now()
	err := waitForReady("socks5 proxy", addr, startErr, 30*time.Second, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "socks5 proxy")
	assert.Contains(t, err.Error(), "bind: address already in use")
	assert.Less(t, time.Since(start), time.Second, "a start error must abort the wait immediately")
}

func TestWaitForReadyTimesOut(t *testing.T) {
	port, r := reserveTCPPort(t)
	r.release()

	err := waitForReady("http proxy", loopbackAddr(port), make(chan error), 300*time.Millisecond, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http proxy")
	assert.Contains(t, err.Error(), "did not accept connections")
}

// 端口上是会接受连接但不应答 SOCKS5 协商的陌生监听器时不得报告就绪，
// 否则端口撞车引发的 EADDRINUSE 会被掩盖。
func TestWaitForReadyRejectsForeignListener(t *testing.T) {
	l, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)
	defer l.Close() //nolint:errcheck
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// 读取对端数据但不回应，模拟 TLS 服务端等待更多字节的行为。
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = conn.Read(buf)
			_ = conn.Close()
		}
	}()

	err = waitForReady("socks5 proxy", l.Addr().String(), make(chan error), 600*time.Millisecond, probeSocks5Greeting)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not answer its protocol probe")
}
