package main_test

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

// socks5 端口预留扫描的候选窗口。窗口刻意落在各平台动态端口段（Linux
// 32768+、macOS/Windows 49152+）之下，减少与内核或其他进程自动分配的端口
// 撞车；窗口内某个端口不可用时逐个跳过即可（见 reserveSocks5PortAt）。
const (
	socks5PortBase = 20000
	socks5PortSpan = 10000
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

// portReservation 以保持监听的方式占住一个 loopback 端口，直到真正的服务
// 即将绑定它。与"挑选后立即释放"的 free-port 模式相反，预留使同一 harness
// 内的多次挑选不可能拿到同一个端口（占位监听器都开着，内核不会把一个端口
// 分发给两个绑定者），也把"挑选与真正绑定之间被并行进程抢走"的窗口从数百
// 毫秒压缩到 release 与 Start 之间的几行代码。CI 的 go test ./... 并行跑
// 多个包，每个包都在做同样的端口挑选，挑完就放的模式曾让 serverPort 与
// socksPort 撞在同一个端口上：socks5 服务器 EADDRINUSE 启动失败，而
// waitForReady 的拨号被先一步启动的 v3 服务端应答，测试带着一个从未启动的
// socks5 组件继续跑，最终以一次莫名其妙的 "Get ...: EOF" 收场。
type portReservation struct {
	listener net.Listener
	packet   net.PacketConn // 仅 SOCKS5 预留需要：同一端口的 UDP 侧
}

// reserveTCPPort 占住一个当前空闲的 loopback TCP 端口，返回端口号与预留。
func reserveTCPPort(t *testing.T) (int, *portReservation) {
	t.Helper()

	l, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)
	r := &portReservation{listener: l}
	// 兜底：正常路径在派发 Start 前同步 release；harness 中途失败时由
	// Cleanup 收尾，测试进程退出前不会泄漏占位监听器。
	t.Cleanup(func() { r.release() })
	return l.Addr().(*net.TCPAddr).Port, r
}

// reserveSocks5Port 挑一个 TCP 与 UDP 两侧都空闲的 loopback 端口并占住它：
// SOCKS5 入口会在同一地址上绑定 TCP 监听器（Start）与 UDP 中继 socket
// （UDP ASSOCIATE 时按 ListenAddr 绑定），因此仅占住 TCP 侧的端口仍然无法
// 保证它能启动。
func reserveSocks5Port(t *testing.T) (int, *portReservation) {
	t.Helper()

	// 随机起点：并行的多个测试二进制不会总是从同一个端口开始扫描而互相推挤。
	return reserveSocks5PortAt(t, socks5PortBase+rand.IntN(socks5PortSpan))
}

// reserveSocks5PortAt 从 start 开始按窗口顺序逐个候选端口扫描，返回第一个
// 双侧都能占住的端口。
//
// 候选端口是显式指定的，而不是反复用 ":0" 让内核挑：内核会把刚释放的端口原样
// 再发一次，而释放占位监听器正是失败分支要做的事，于是"某一侧恰好不可用"的候选
// 会让重试循环原地打转——20 次重试全落在同一个端口上，一次都没能前进。
// 2026-10-01 的 windows-arm64 CI 就是这样报出 "no loopback port free on both
// tcp and udp" 的（同一个提交几分钟前在 PR 分支上还是绿的）。显式换端口保证
// 每次尝试都是新候选，被单个端口卡住的重试因此不可能发生。
func reserveSocks5PortAt(t *testing.T, start int) (int, *portReservation) {
	t.Helper()

	var lastErr error
	for i := range socks5PortSpan {
		port := socks5PortBase + (start-socks5PortBase+i)%socks5PortSpan
		r, err := tryReserveSocks5Port(loopbackAddr(port))
		if err != nil {
			// 记下最后一个错误：扫描全窗口都失败时，它是唯一能说明"是 TCP 侧
			// 被占、UDP 侧被占，还是端口被系统保留"的证据。
			lastErr = err
			continue
		}
		// 兜底：正常路径在派发 Start 前同步 release；harness 中途失败时由
		// Cleanup 收尾，测试进程退出前不会泄漏占位监听器。
		t.Cleanup(func() { r.release() })
		return port, r
	}
	t.Fatalf("no loopback port free on both tcp and udp in [%d, %d), last error: %v",
		socks5PortBase, socks5PortBase+socks5PortSpan, lastErr)
	return 0, nil
}

// tryReserveSocks5Port 尝试在 addr 上完成双侧预留。任一侧不可用即返回错误，
// 且不留下任何已占用的 socket，由调用方换下一个候选端口。
func tryReserveSocks5Port(addr string) (*portReservation, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		// TCP 侧已经拿到手：这里必须自己关掉，否则失败分支会把刚释放的端口
		// 又占回去（调用方的下一个候选未必是它，但泄漏是实打实的）。
		_ = l.Close()
		return nil, err
	}
	return &portReservation{listener: l, packet: pc}, nil
}

// release 把端口交还给即将启动的真正服务，必须在派发 Start 的前一行调用。
// 它是幂等的，可安全地在正常路径与 Cleanup 中各调用一次。
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

// waitForReady 轮询 addr 直到其接受 TCP 连接且（可选的）协议探测通过，
// 确保测试框架只在异步启动的服务器真正开始监听后才继续。startErr 上发布的
// 启动失败会立即以该错误中止：否则等待超时会把 "address already in use"
// （或任何其他启动失败）伪装成就绪超时。probe 为 nil 时仅要求连接被接受；
// 非 nil 时还要求探测通过——单纯能拨通不再等价于就绪：端口撞车时拨号会被
// 占住该端口的邻居组件（或其他进程）应答，组件自身的 EADDRINUSE 错误又
// 迟到于探测拨号，测试就会带着一个从未启动的组件继续跑。
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

// probeSocks5Greeting 用一次真实的 SOCKS5 协商验证连接的对端确是我们的
// SOCKS5 服务端：发送版本 5 问候并期待方法选择应答。只有 SOCKS5 服务器会
// 以首字节 0x05 应答；端口撞车时接管的 v3 TLS 服务端只会让探测在读应答时
// 超时，waitForReady 便会转而盯住组件自己的启动错误。
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
	// socks5 代理只在 Start 报告成功之后才被追加，使清理函数只针对真正启动过
	// 的组件——Start 失败时它已经把自己创建的监听器释放掉了（见
	// Socks5Server.Start/Close）。
	closers []func()

	cleanupOnce sync.Once
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{}

	// 每个监听器都使用内核选择的端口，且以预留的方式占住直到对应组件
	// 即将绑定：同一台机器上本包的两个运行实例（另一个终端、IDE 测试
	// 运行、另一个检出目录）不会互相争抢监听端口，本 harness 内部也不会
	// 自相撞车，端口被占用时必须明显失败，而不是被误认为仅仅是启动缓慢。
	serverPort, serverRes := reserveTCPPort(t)
	socksPort, socksRes := reserveSocks5Port(t)
	httpPort, httpRes := reserveTCPPort(t)
	// 三份预留同时保持监听，内核不可能复用同一端口；断言是廉价的防线，
	// 万一被打破，失败信息应直指端口撞车，而不是下游测试里莫名的 EOF。
	require.True(t, serverPort != socksPort && serverPort != httpPort && socksPort != httpPort,
		fmt.Sprintf("harness ports collided: server=%d socks=%d http=%d", serverPort, socksPort, httpPort))
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

	// 端口交还与派发 Start 之间只有几行代码，窗口小到可以忽略。
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

	socksRes.release()
	socksErr := make(chan error, 1)
	go func() {
		socksErr <- socksServer.Start()
	}()
	require.NoError(t, waitForReady("socks5 proxy", h.socksAddr, socksErr, readinessTimeout, probeSocks5Greeting))
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
		// 按启动顺序的逆序执行：先代理，再客户端，最后是客户端所连接的服务器。
		for _, closer := range slices.Backward(h.closers) {
			closer()
		}
	})
}

// socks5DialFunc 返回一个 http.Transport 可用的 DialContext：它经 SOCKS5 入口
// （无认证）连到目标地址。
//
// x/net/proxy 的 SOCKS5 客户端不在协商成功后残留 deadline，因此调用方不再需要
// 像旧库时代那样手工 SetDeadline(time.Time{}) 清理握手 deadline。
func socks5DialFunc(t *testing.T, socksAddr string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	require.NoError(t, err)
	cd, ok := d.(xproxy.ContextDialer)
	require.True(t, ok, "x/net/proxy SOCKS5 dialer must support contexts")
	return cd.DialContext
}

// TestV3Integration_Socks5Proxy 测试通过 v3 隧道经 SOCKS5 代理发起 HTTP 请求
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

// TestV3Integration_CloseWrite 测试通过 SOCKS5 代理进行 TCP 半关闭。
//
// 这里断言的是端到端行为：SOCKS5 入口返回的连接必须实现 CloseWrite，且半关闭要
// 一路传播到目标、允许反方向继续传输。旧实现用 txthinking/socks5 的 *socks5.Client
// 作为连接类型，它没有 CloseWrite，于是 relayTCP 的半关闭被静默跳过——当时的测试
// 只能先断言出具体类型、再手工取出底层的 *net.TCPConn 才能触发半关闭。
func TestV3Integration_CloseWrite(t *testing.T) {
	h := newTestHarness(t)

	msg := "hello-closewrite"

	// 用裸 TCP + 手工握手拨号，而不是经 x/net/proxy：后者返回的是一个不透明的
	// *socks.Conn 包装类型，拿不到底层 *net.TCPConn，也就无法在本机触发半关闭。
	// 手工握手把断言点放回真正要验证的能力上——SOCKS5 入口把客户端的半关闭一路
	// 传播到目标，并允许反方向继续传输。
	conn := socks5HandshakeConnect(t, h.socksAddr, h.echoAddr)
	defer conn.Close() //nolint:errcheck

	_, err := conn.Write([]byte(msg))
	require.NoError(t, err)

	// 关闭写侧（半关闭）。
	require.NoError(t, conn.CloseWrite())

	// 读取响应：半关闭不得影响反方向。
	buf := make([]byte, 1024)
	nr, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:nr]))
}

// socks5HandshakeConnect 与 socksAddr 完成一次无认证 SOCKS5 握手并发起 CONNECT，
// 返回底层 *net.TCPConn（因此调用方可以 CloseWrite 触发半关闭）。
func socks5HandshakeConnect(t *testing.T, socksAddr, target string) *net.TCPConn {
	t.Helper()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	// 握手：VER + NMETHODS + METHODS（只提供"无认证"）。
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	greeting := make([]byte, 2)
	_, err = io.ReadFull(conn, greeting)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, greeting, "server must select no-auth")

	// CONNECT：VER + CMD + RSV + ATYP=domain + 长度 + 域名 + 端口。
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

	// 应答：VER + REP + RSV + ATYP + BND.ADDR + BND.PORT。
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

// TestReserveSocks5PortHoldsTCPAndUDP 固化了端口预留的契约：预留保持 TCP
// 占位监听器与 UDP 占位 socket 打开，因此在 release 之前两侧都无法被其他
// socket 绑定；release 之后 SOCKS5 入口需要的 TCP+UDP 双绑定即可成功。
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

// TestReserveSocks5PortSkipsBlockedCandidate 固化"候选端口在某一侧不可用时必须
// 换下一个，而不是原地重试"：Windows 上内核会把刚释放的端口再发一次，依赖
// ":0" 的重试循环会一直撞在同一个端口上（见 reserveSocks5PortAt）。
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

// blockedSocks5Candidate 在扫描窗口内占住一个候选端口的 UDP 侧，使它在"双侧
// 都要空闲"的判定下不可用，而 TCP 侧仍然空闲。
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

// TestWaitForReadyReportsStartError 固化了快速失败契约：启动失败的服务器
// 必须以其真实错误上报，而不是伪装成就绪超时。
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

// TestWaitForReadyTimesOut 覆盖剩余的情况：没有任何监听且没有启动错误可上报。
func TestWaitForReadyTimesOut(t *testing.T) {
	// 只需要一个曾经空闲的地址：占位监听器此刻关闭，地址上没有任何监听。
	port, r := reserveTCPPort(t)
	r.release()

	err := waitForReady("http proxy", loopbackAddr(port), make(chan error), 300*time.Millisecond, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http proxy")
	assert.Contains(t, err.Error(), "did not accept connections")
}

// TestWaitForReadyRejectsForeignListener 固化了协议探测的契约：端口上
// 是一个会接受连接但不应答 SOCKS5 协商的陌生监听器时，waitForReady 不得
// 报告就绪。这正是端口撞车事故里 socks5 探测拨号被 v3 TLS 服务端应答、
// 从而掩盖 EADDRINUSE 启动错误的失败模式。
func TestWaitForReadyRejectsForeignListener(t *testing.T) {
	// 用一个只接受连接的哑监听器扮演"陌生进程"。
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
