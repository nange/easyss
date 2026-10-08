package server

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/vpn"
)

// startFakeSOCKS5 起一个最小的 SOCKS5 代理：它按 RFC 1928 完成握手，记录 CONNECT
// 的目标，再把连接接到该目标上。用它来断言"mesh 连接确实经 SOCKS5 出网"，而不必
// 依赖一个真实的 easyss-headless。
func startFakeSOCKS5(t *testing.T) (addr string, targets <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake socks5: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan string, 16)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(br, greeting); err != nil || greeting[0] != 5 {
					return
				}
				if _, err := io.ReadFull(br, make([]byte, int(greeting[1]))); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				head := make([]byte, 4)
				if _, err := io.ReadFull(br, head); err != nil || head[1] != 1 {
					return
				}
				var host string
				switch head[3] {
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(br, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 4:
					b := make([]byte, 16)
					if _, err := io.ReadFull(br, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 3:
					l := make([]byte, 1)
					if _, err := io.ReadFull(br, l); err != nil {
						return
					}
					b := make([]byte, int(l[0]))
					if _, err := io.ReadFull(br, b); err != nil {
						return
					}
					host = string(b)
				default:
					return
				}
				pb := make([]byte, 2)
				if _, err := io.ReadFull(br, pb); err != nil {
					return
				}
				target := net.JoinHostPort(host, strconv.Itoa(int(pb[0])<<8|int(pb[1])))
				select {
				case ch <- target:
				default:
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer func() { _ = up.Close() }()
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				done := make(chan struct{}, 1)
				go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
				_, _ = io.Copy(c, up)
				<-done
			}(c)
		}
	}()

	return ln.Addr().String(), ch
}

// startMeshTestDERP 起一个进程内中继（真实 TLS + 真实 derpserver），返回它的
// 对外 host:port、公钥与自签证书（后者用来充当 mesh_peers[].ca_file）。
func startMeshTestDERP(t *testing.T) (addr string, publicKey key.NodePublic, certPEM []byte) {
	t.Helper()
	srv := vpn.NewDERPServer(key.NewNode())
	hs := httptest.NewUnstartedServer(srv.Handler())
	hs.StartTLS()
	t.Cleanup(func() {
		hs.Close()
		_ = srv.Close()
	})
	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatalf("parse test relay URL %q: %v", hs.URL, err)
	}
	cert := hs.Certificate()
	if cert == nil {
		t.Fatal("the test relay has no certificate")
	}
	return u.Host, srv.PublicKey(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// writeMeshCAFile 把中继的自签证书写成 mesh_peers[].ca_file 指向的文件。
func writeMeshCAFile(t *testing.T, certPEM []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer-ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("write the peer CA file: %v", err)
	}
	return path
}

// meshTestFileConfig 造一份启用了 VPN 与 mesh 的服务端配置（它的 derp_addr 指向本机
// 一个没人监听的端口：startDERPMesh 只用到地址字符串，不拨它）。
func meshTestFileConfig(peerAddr, peerProxy, meshKey string) *config.FileConfig {
	return &config.FileConfig{
		Server: config.ServerConfig{
			Listen: ":443",
			Domain: "a.example.com",
			VPN: config.VPNConfig{
				Enabled:  true,
				DERPAddr: "a.example.com:443",
				MeshKey:  meshKey,
				MeshPeers: []config.MeshPeer{{
					Addr:  peerAddr,
					Proxy: peerProxy,
				}},
			},
		},
	}
}

// TestMeshDialersFor 固定"每个对端一条经隧道的出网路径"这条翻译规则：对端自带
// proxy 时用它，否则复用顶层 next_proxy 的实例；两者都没有必须报错（内嵌 DERP 只
// 接待回环来源，直连对端公网端口不可能成功）。
func TestMeshDialersFor(t *testing.T) {
	const timeout = 5 * time.Second

	t.Run("对端自带 proxy 时优先于顶层 next_proxy", func(t *testing.T) {
		cfg := meshTestFileConfig("relay-b.example.com:443", "socks5://127.0.0.1:1081", "k")
		shared, err := nextproxy.New("socks5://127.0.0.1:1080", false, true)
		if err != nil {
			t.Fatal(err)
		}
		peers, err := meshDialersFor(cfg, shared, timeout)
		if err != nil {
			t.Fatalf("meshDialersFor: %v", err)
		}
		if len(peers) != 1 || peers[0].Addr != "relay-b.example.com:443" {
			t.Fatalf("peers = %+v, want one peer for relay-b", peers)
		}
		if peers[0].Dial == nil {
			t.Error("the peer has no dialer")
		}
	})

	t.Run("对端没有 proxy 时复用顶层实例", func(t *testing.T) {
		cfg := meshTestFileConfig("relay-b.example.com:443", "", "k")
		shared, err := nextproxy.New("socks5://127.0.0.1:1080", false, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := meshDialersFor(cfg, shared, timeout); err != nil {
			t.Fatalf("meshDialersFor: %v", err)
		}
	})

	t.Run("两者都没有时报错", func(t *testing.T) {
		cfg := meshTestFileConfig("relay-b.example.com:443", "", "k")
		if _, err := meshDialersFor(cfg, nil, timeout); err == nil {
			t.Error("meshDialersFor accepted a peer with no proxy and no next_proxy instance")
		}
	})

	t.Run("proxy 非法时报错", func(t *testing.T) {
		cfg := meshTestFileConfig("relay-b.example.com:443", "http://127.0.0.1:8080", "k")
		if _, err := meshDialersFor(cfg, nil, timeout); err == nil {
			t.Error("meshDialersFor accepted a non-socks5 proxy")
		}
	})
}

// TestMeshDialerTrafficGoesThroughTheProxy 断言拨号器真的经 SOCKS5 发出 CONNECT，
// 且目标正是 mesh_peers[].addr：这就是"mesh 连接不是直连对端"的可观测证据。
func TestMeshDialerTrafficGoesThroughTheProxy(t *testing.T) {
	relayAddr, _, _ := startMeshTestDERP(t)
	proxyAddr, targets := startFakeSOCKS5(t)

	cfg := meshTestFileConfig(relayAddr, "socks5://"+proxyAddr, "shared-key")
	peers, err := meshDialersFor(cfg, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("meshDialersFor: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := peers[0].Dial(ctx, "tcp", relayAddr)
	if err != nil {
		t.Fatalf("dial through the SOCKS5 proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case got := <-targets:
		if got != relayAddr {
			t.Errorf("SOCKS5 CONNECT target = %q, want %q", got, relayAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the SOCKS5 proxy saw no CONNECT")
	}
}

// TestMeshTLSConfig 固定 ca_file 的语义：留空用系统根证书（certmagic 的情形），
// 给出时必须是可用的 PEM 证书。
func TestMeshTLSConfig(t *testing.T) {
	t.Run("留空表示系统根证书", func(t *testing.T) {
		cfg, err := meshTLSConfig(config.MeshPeer{Addr: "relay-b.example.com:443"})
		if err != nil {
			t.Fatalf("meshTLSConfig: %v", err)
		}
		if cfg != nil {
			t.Errorf("meshTLSConfig = %+v, want nil (system roots)", cfg)
		}
	})

	t.Run("给出可用证书时用它作根", func(t *testing.T) {
		caFile := writeTestCAFile(t)
		cfg, err := meshTLSConfig(config.MeshPeer{Addr: "relay-b.example.com:443", CAFile: caFile})
		if err != nil {
			t.Fatalf("meshTLSConfig: %v", err)
		}
		if cfg == nil || cfg.RootCAs == nil {
			t.Fatal("meshTLSConfig returned no RootCAs")
		}
		if cfg.InsecureSkipVerify {
			t.Error("the mesh client must verify the peer's certificate")
		}
	})

	t.Run("文件不存在或不是证书时报错", func(t *testing.T) {
		if _, err := meshTLSConfig(config.MeshPeer{CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
			t.Error("meshTLSConfig accepted a missing ca_file")
		}
		notPEM := filepath.Join(t.TempDir(), "not-a-cert.pem")
		if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := meshTLSConfig(config.MeshPeer{CAFile: notPEM}); err == nil {
			t.Error("meshTLSConfig accepted a file that carries no certificate")
		}
	})
}

// TestStartDERPMeshAndShutdown 固定服务端侧的装配与收尾：mesh 客户端经 SOCKS5 连上
// 对端中继（日志可见）、日志里**没有 mesh_key**、Shutdown 会把 mesh 拆掉且幂等。
func TestStartDERPMeshAndShutdown(t *testing.T) {
	var buf syncBuffer
	prev := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { log.SetLogger(prev) })

	relayAddr, relayKey, relayCert := startMeshTestDERP(t)
	proxyAddr, targets := startFakeSOCKS5(t)

	const meshKey = "the-shared-mesh-passphrase"
	cfg := meshTestFileConfig(relayAddr, "socks5://"+proxyAddr, meshKey)
	// 测试中继用的是自签证书：把它的证书当作该对端的 ca_file，正是手工证书部署
	// 的形态（也是 meshTLSConfig 存在的理由）。
	cfg.Server.VPN.MeshPeers[0].CAFile = writeMeshCAFile(t, relayCert)

	s := &Server{}
	s.meshCtx, s.meshCancel = context.WithCancel(t.Context())
	if err := s.startDERPMesh(cfg, vpn.NewDERPServer(key.NewNode()), nil, 5*time.Second); err != nil {
		t.Fatalf("startDERPMesh: %v", err)
	}
	if s.mesh == nil {
		t.Fatal("startDERPMesh did not store the mesh")
	}

	select {
	case got := <-targets:
		if got != relayAddr {
			t.Errorf("SOCKS5 CONNECT target = %q, want %q", got, relayAddr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the mesh client never dialled the peer through the SOCKS5 proxy")
	}

	// 连上之后必须留下"连到了哪台中继"这一行（公钥是排障的关键证据）。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if buf.contains("derp mesh peer connected") && buf.contains(relayKey.ShortString()) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	out := buf.String()
	if !buf.contains("derp mesh peer connected") {
		t.Errorf("no log line about the established mesh peer:\n%s", out)
	}
	if !buf.contains("derp mesh enabled") {
		t.Errorf("no log line about the enabled mesh:\n%s", out)
	}
	if strings.Contains(out, meshKey) {
		t.Errorf("the mesh key leaked into the log:\n%s", out)
	}

	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if s.mesh != nil {
		t.Error("Shutdown must release the mesh")
	}
	// 幂等：退出序列与信号路径可能各调一次。
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// TestMeshDisabledLeavesNoState 守护"未配置 mesh 时与既有版本一致"：没有 mesh_key
// 就不构造 Mesh，Shutdown 也不会去碰它。
func TestMeshDisabledLeavesNoState(t *testing.T) {
	s := &Server{}
	if s.mesh != nil || s.meshCancel != nil {
		t.Fatal("a fresh Server must not carry mesh state")
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if s.mesh != nil {
		t.Error("Shutdown must leave the mesh nil when there is none")
	}
}

// ---- 测试辅助 ----

// syncBuffer 是并发安全的日志缓冲（mesh 的日志来自多个 goroutine）。
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) contains(sub string) bool { return strings.Contains(s.String(), sub) }

// writeTestCAFile 生成一份自签证书并写成 PEM 文件，用它验证 ca_file 的加载路径
// （不依赖任何外部测试数据）。
func writeTestCAFile(t *testing.T) string {
	t.Helper()
	_, cert, err := testSelfSignedCert(t)
	if err != nil {
		t.Fatalf("generate a test certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, cert, 0o600); err != nil {
		t.Fatalf("write test CA file: %v", err)
	}
	return path
}

// testSelfSignedCert 返回 (DER 证书, PEM 编码) 的自签证书。
func testSelfSignedCert(t *testing.T) (der, certPEM []byte, err error) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "easyss-mesh-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
