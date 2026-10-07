package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"

	"github.com/nange/easyss/v3/client/proxy"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

// derpEnvHelperEnv 把测试二进制的同一个用例切成"父进程（断言）"与"子进程（真实
// 拨号）"两半。子进程是必需的：某个 gVisor 之外的原因——x/net/proxy 用 sync.Once
// 缓存 ALL_PROXY，进程内只读一次——一旦本进程在任何时刻拨过一次号，缓存就固定了。
// 只有在全新的进程里才能确定"我们设置的 ALL_PROXY 真的被读到"。
const derpEnvHelperEnv = "EASYSS_TEST_DERP_ENV_HELPER"

// TestTailcatDERPDialsUseAllProxy 是 DERP 私有化的**正向对照**：它证明 tailscale
// 的 DERP 拨号确实会走 ALL_PROXY 指定的 SOCKS5。
//
// 这条性质是整个方案的地基：客户端把 ALL_PROXY 指向本进程内的 DERP 入口
// （见 derpshim.go），服务端只接待来自回环的 /derp（见 vpn.NewDERPMount）。如果
// tailscale 在升级中改了 netns 的拨号路径或构建标签，DERP 会静默退回直连——而直连
// 现在只会拿到伪装页面，表现为"VPN 莫名其妙连不上"。有了这条用例，那种升级会在 CI
// 里直接红掉，而不是留给用户排查。
func TestTailcatDERPDialsUseAllProxy(t *testing.T) {
	if os.Getenv(derpEnvHelperEnv) == "1" {
		runDERPEnvHelper(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestTailcatDERPDialsUseAllProxy$", "-test.v")
	cmd.Env = append(os.Environ(), derpEnvHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), derpEnvHelperObserved) {
		t.Fatalf("tailscale's DERP dial did not go through ALL_PROXY:\n%s", out)
	}
}

// derpEnvHelperObserved 是子进程在观察到 CONNECT 时打印的标记。
const derpEnvHelperObserved = "observed DERP CONNECT"

// runDERPEnvHelper 在子进程里跑：起一个只记录 CONNECT 目标的假 SOCKS5，把
// ALL_PROXY 指向它，然后用 tailscale 自己的 netns 拨号器拨一次 DERP 地址。
//
// 这里刻意不用完整的 tailcat 客户端来触发拨号：它要先跑 netcheck 才会去连 DERP，
// 而那一步依赖"有一台可达的中继"，会把用例变成慢且脆的集成测试。netns 拨号器正是
// derphttp 拨 DERP 用的那一个（见 derp/derphttp 的 dialContext），因此这里覆盖的
// 就是真正生效的那一层；DERP 隧道的端到端另有 vpn/node 与 server/handler 的用例。
func runDERPEnvHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	observed := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRecordingSOCKS5(conn, observed)
		}
	}()

	// derp.invalid 是一个永远解析不出结果的保留域名：能观察到 CONNECT 就同时证明了
	// 两件事——拨号确实经 SOCKS5 出去，而且**主机名是原样交给代理的**（代理侧解析，
	// 这正是 easyss 的入口赖以分流的前提）。
	const derpAddr = "derp.invalid:8443"
	if err := os.Setenv(allProxyEnv, "socks5://"+ln.Addr().String()); err != nil {
		t.Fatalf("set %s: %v", allProxyEnv, err)
	}

	dialer := netns.NewDialer(logger.Discard, netmon.NewStatic())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// 这个拨号会成功：假 SOCKS5 回了成功应答，于是我们拿到的是一条指向它的连接
	// （DERP 的 TLS 握手由上层的 derphttp 负责，这里不涉及）。
	conn, err := dialer.DialContext(ctx, "tcp", derpAddr)
	if err != nil {
		t.Fatalf("dial through the recording SOCKS5: %v", err)
	}
	_ = conn.Close()

	select {
	case target := <-observed:
		if target != derpAddr {
			t.Fatalf("the SOCKS5 CONNECT target = %q, want %q (the host name must reach the proxy unresolved)", target, derpAddr)
		}
		fmt.Printf("%s %s\n", derpEnvHelperObserved, target)
	case <-time.After(5 * time.Second):
		t.Fatalf("no SOCKS5 CONNECT arrived: tailscale dialed %s directly instead of using %s", derpAddr, allProxyEnv)
	}
}

// serveRecordingSOCKS5 是一个最小 SOCKS5 服务端：做完无认证协商、记录 CONNECT
// 目标、回一个成功应答，然后短暂保持连接，让调用方的 TLS 握手自然失败。
func serveRecordingSOCKS5(conn net.Conn, observed chan<- string) {
	defer conn.Close() //nolint:errcheck

	var head [4]byte
	// 问候：VER NMETHODS METHODS...
	if _, err := io.ReadFull(conn, head[:2]); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, head[:4]); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 0x01:
		var v4 [4]byte
		if _, err := io.ReadFull(conn, v4[:]); err != nil {
			return
		}
		host = net.IP(v4[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return
		}
		host = string(name)
	case 0x04:
		var v6 [16]byte
		if _, err := io.ReadFull(conn, v6[:]); err != nil {
			return
		}
		host = net.IP(v6[:]).String()
	default:
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	select {
	case observed <- net.JoinHostPort(host, strconv.Itoa(port)):
	default:
	}
	// 成功应答（BND.ADDR/BND.PORT 全零）：调用方随后会开始 TLS 握手，而这里
	// 不会再回应它——用例只关心 CONNECT 目标。
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	time.Sleep(2 * time.Second)
}

// TestDERPShimWiring 固定 DERP 入口的接线：端口由 peer_port 派生（必须确定性——
// ALL_PROXY 的值在进程内只读一次，随机端口会让第二次会话指向一个已关闭的端口）、
// ALL_PROXY 指向该入口，close 之后还原进程原有的值。
func TestDERPShimWiring(t *testing.T) {
	if _, err := derpShimPort(0); err == nil {
		t.Error("a non-positive peer_port must be rejected")
	}
	if _, err := derpShimPort(65535); err == nil {
		t.Error("a peer_port with no room for the entry port must be rejected")
	}
	port, err := derpShimPort(6080)
	if err != nil || port != 6081 {
		t.Fatalf("derpShimPort(6080) = %d, %v; want 6081", port, err)
	}
	// 真正开监听的部分用当前空闲端口，避免固定端口在忙的机器上假失败。
	shimPort := freePort(t)
	peerPort := shimPort - 1
	if peerPort <= 0 {
		t.Skipf("no usable port pair around %d", shimPort)
	}

	const original = "socks5://192.0.2.9:1080"
	t.Setenv(allProxyEnv, original)

	// 借用一个没有 transport 的 handler：本用例只覆盖 shim 的监听/环境变量接线，
	// 不会真的经由它拨号。
	handler := proxy.NewStreamHandler(nil, nil, shaper.Config{}, 0)
	shim, err := startDERPShim(handler, protocol.MethodAES256GCM, sharedconfig.NewTimeouts(5*time.Second), peerPort)
	if err != nil {
		t.Fatalf("startDERPShim: %v", err)
	}
	if got := os.Getenv(allProxyEnv); got != "socks5://"+shim.addr {
		t.Errorf("%s = %q, want the shim address %q", allProxyEnv, got, shim.addr)
	}
	shim.close()
	if got := os.Getenv(allProxyEnv); got != original {
		t.Errorf("after close, %s = %q, want the original %q", allProxyEnv, got, original)
	}
	shim.close() // 幂等

	// 端口被占用时必须是一个明确的启动错误，而不是静默换端口——换端口会让已经
	// 缓存了旧地址的后续会话指向一个没人监听的端口。
	blocker, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(shimPort)))
	if err != nil {
		t.Skipf("the entry port %d is not available for the collision case: %v", shimPort, err)
	}
	defer blocker.Close() //nolint:errcheck
	if _, err := startDERPShim(handler, protocol.MethodAES256GCM, sharedconfig.NewTimeouts(5*time.Second), peerPort); err == nil {
		t.Error("startDERPShim must fail when the entry port is already in use")
	}
}
