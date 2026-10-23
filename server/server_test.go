package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	serverconfig "github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/vpn"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

// logRecorder 捕获包级日志器的记录。server 包的用例不并行，替换包级日志器是安全的。
type logRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *logRecorder) WithGroup(string) slog.Handler      { return r }

// warnings 返回级别不低于 Warn 的记录。
func (r *logRecorder) warnings() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []slog.Record
	for _, rec := range r.records {
		if rec.Level >= slog.LevelWarn {
			out = append(out, rec)
		}
	}
	return out
}

func captureServerLogs(t *testing.T) *logRecorder {
	t.Helper()
	rec := &logRecorder{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })
	return rec
}

// TestShutdownClosesEmbeddedDERP 固定 Shutdown 会显式收尾内嵌 DERP：它的连接全部是 Hijack 走的，
// http.Server.Shutdown 不管也不等待这类连接，少了这一步中继的收发 goroutine 会留在进程里。
func TestShutdownClosesEmbeddedDERP(t *testing.T) {
	s := &Server{derp: vpn.NewDERPServer(key.NewNode(), 0)}

	require.NoError(t, s.Shutdown(context.Background()))
	require.Nil(t, s.derp, "Shutdown must release the embedded DERP server")
}

// TestShutdownWithoutVPN 守护未启用 VPN 时 Shutdown 是空操作。
func TestShutdownWithoutVPN(t *testing.T) {
	s := &Server{}
	require.NoError(t, s.Shutdown(context.Background()))
}

func TestCertmagicStoragePathForExecutable(t *testing.T) {
	exe := filepath.Join("tmp", "easyss", "easyss-server")
	require.Equal(t, filepath.Join("tmp", "easyss", "certmagic"), certmagicStoragePathForExecutable(exe))
}

func TestNewDoesNotValidateProtocols(t *testing.T) {
	// 老配置里的 transport.protocols 由 json.Unmarshal 忽略，New 不读它。
	require.NoError(t, mustNewServer(t))
}

// TestNewValidatesConfig 固定 server.New 也是校验入口：导出 API 会被绕过
// config.LoadConfig 的调用方直接手搓 FileConfig，校验不能只留在配置文件路径上。
func TestNewValidatesConfig(t *testing.T) {
	cfg := &serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{
			Host:           "example.com",
			AllowedMethods: []string{"aes-gcm"},
		},
	}
	_, err := New(cfg)
	require.ErrorContains(t, err, "server.allowed_methods")

	cfg = &serverconfig.FileConfig{
		Server:    serverconfig.ServerConfig{Host: "example.com"},
		Transport: serverconfig.TransportConfig{H2MaxFrameSize: 10000},
	}
	_, err = New(cfg)
	require.ErrorContains(t, err, "transport.h2_max_frame_size")

	cfg = &serverconfig.FileConfig{
		Server:    serverconfig.ServerConfig{Host: "example.com"},
		Transport: serverconfig.TransportConfig{H2RecvBufConn: 1000},
	}
	_, err = New(cfg)
	require.ErrorContains(t, err, "transport.h2_recv_buf_conn")

	// 非法端口与带端口的 bind 必须在 New 就失败，而不是留到 Start 的 net.Listen。
	cfg = &serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Host: "example.com", Port: 70000},
	}
	_, err = New(cfg)
	require.ErrorContains(t, err, "server.port")

	cfg = &serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Host: "example.com", Bind: "127.0.0.1:443"},
	}
	_, err = New(cfg)
	require.ErrorContains(t, err, "server.bind")
}

func mustNewServer(t *testing.T) error {
	t.Helper()
	_, err := New(&serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Host: "example.com"},
	})
	return err
}

func TestShouldRetryFreshCertificate(t *testing.T) {
	require.True(t, shouldRetryFreshCertificate(acme.Problem{
		Type:   acme.ProblemTypeAlreadyReplaced,
		Status: http.StatusConflict,
	}))
	require.True(t, shouldRetryFreshCertificate(acme.Problem{
		Type:   acme.ProblemTypeMalformed,
		Status: http.StatusNotFound,
	}))
	// 同一个 Problem 类型下，detail 仍用于区分 ARI replaces 的具体拒绝。
	require.True(t, shouldRetryFreshCertificate(acme.Problem{
		Type:   acme.ProblemTypeMalformed,
		Status: http.StatusBadRequest,
		Detail: "Could not validate ARI 'replaces' field",
	}))
	require.True(t, shouldRetryFreshCertificate(fmt.Errorf("certmagic: %w", acme.Problem{
		Type:   acme.ProblemTypeMalformed,
		Status: http.StatusBadRequest,
		Detail: "Requested certificate was not found",
	})))

	require.True(t, shouldRetryFreshCertificate(errString("Could not validate ARI 'replaces' field")))
	require.True(t, shouldRetryFreshCertificate(errString("Requested certificate was not found")))
	require.False(t, shouldRetryFreshCertificate(errString("dial tcp: i/o timeout")))
	require.False(t, shouldRetryFreshCertificate(acme.Problem{
		Type:   acme.ProblemTypeRateLimited,
		Status: http.StatusTooManyRequests,
	}))
}

func TestCleanCertmagicDomainAssets(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	domain := "example.com"
	issuerKey := (&certmagic.ACMEIssuer{CA: certmagic.DefaultACME.CA}).IssuerKey()

	keys := []string{
		certmagic.StorageKeys.SiteCert(issuerKey, domain),
		certmagic.StorageKeys.SitePrivateKey(issuerKey, domain),
		certmagic.StorageKeys.SiteMeta(issuerKey, domain),
	}
	for _, key := range keys {
		require.NoError(t, storage.Store(context.Background(), key, []byte("test")))
		require.True(t, storage.Exists(context.Background(), key))
	}

	require.NoError(t, cleanCertmagicDomainAssets(context.Background(), storage, domain))
	for _, key := range keys {
		require.False(t, storage.Exists(context.Background(), key))
	}
}

// TestCertmagicAcceptsPublicIPSubject 守住 IP-only 模式的依赖假设：certmagic 用硬编码表
// 判断公网 CA 是否支持 IP 证书，升级 certmagic 时本测试变红；私有地址须与 validateTLS 一致地被拒。
func TestCertmagicAcceptsPublicIPSubject(t *testing.T) {
	var cmCfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cmCfg, nil
		},
	})
	t.Cleanup(cache.Stop)

	cmCfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: t.TempDir()},
	})

	acmeCfg := certmagic.DefaultACME
	acmeCfg.Agreed = true
	acmeCfg.Email = "admin@example.com"
	issuer := certmagic.NewACMEIssuer(cmCfg, acmeCfg)

	ctx := context.Background()
	require.NoError(t, issuer.PreCheck(ctx, []string{"1.1.1.1"}, false), "LE 必须仍然支持公网 IP 证书")

	err := issuer.PreCheck(ctx, []string{"192.168.1.10"}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not qualify for a public certificate")
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRandomEmail(t *testing.T) {
	email := randomEmail()
	matched, err := regexp.MatchString(`^admin_[0-9a-f]{16}@gmail\.com$`, email)
	require.NoError(t, err)
	require.True(t, matched, "unexpected email format: %s", email)
}

func TestFindExistingACMEEmail(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "certmagic")

	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	oldEmailDir := filepath.Join(usersPath, "old@example.com")
	newEmailDir := filepath.Join(usersPath, "new@example.com")

	require.NoError(t, os.MkdirAll(oldEmailDir, 0700))
	require.NoError(t, os.MkdirAll(newEmailDir, 0700))

	oldTime := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(oldEmailDir, oldTime, oldTime))

	result := findExistingACMEEmail(storagePath)
	require.Equal(t, "old@example.com", result)
}

func TestFindExistingACMEEmail_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestFindExistingACMEEmail_NoUsers(t *testing.T) {
	tmpDir := t.TempDir()

	acmePath := filepath.Join(tmpDir, "acme", "some-ca")
	require.NoError(t, os.MkdirAll(acmePath, 0700))

	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestResolveEmail_Configured(t *testing.T) {
	s := &Server{
		cfg: &serverconfig.FileConfig{
			Server: serverconfig.ServerConfig{Email: "user@example.com"},
		},
	}
	s.resolveEmail(t.TempDir())
	require.Equal(t, "user@example.com", s.cfg.Server.Email)
}

func TestResolveEmail_Reuse(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "certmagic")

	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	existingEmail := "reused@example.com"
	require.NoError(t, os.MkdirAll(filepath.Join(usersPath, existingEmail), 0700))

	s := &Server{
		cfg: &serverconfig.FileConfig{
			Server: serverconfig.ServerConfig{Email: ""}, // 未配置
		},
	}
	s.resolveEmail(storagePath)
	require.Equal(t, existingEmail, s.cfg.Server.Email)
}

func TestResolveEmail_Generated(t *testing.T) {
	s := &Server{
		cfg: &serverconfig.FileConfig{
			Server: serverconfig.ServerConfig{Email: ""},
		},
	}
	s.resolveEmail(t.TempDir())

	matched, err := regexp.MatchString(`^admin_[0-9a-f]{16}@gmail\.com$`, s.cfg.Server.Email)
	require.NoError(t, err)
	require.True(t, matched, "unexpected generated email format: %s", s.cfg.Server.Email)
}

// TestBuildHTTPServerUsesListenAddr 固定监听地址只由 ServerConfig.ListenAddr
// 格式化：bind 与 port 必须原样进入 http.Server.Addr。
func TestBuildHTTPServerUsesListenAddr(t *testing.T) {
	srv := buildHTTPServer(&serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Bind: "127.0.0.1", Port: 8443},
	}, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, "127.0.0.1:8443", srv.Addr)

	srv = buildHTTPServer(&serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Port: 443},
	}, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, ":443", srv.Addr)
}

// TestBuildHTTPServerUploadFlowControl 用字面量（而非常量引用）固定上传侧参数，缩小
// 常量同样会让本测试失败：吞吐 ≈ 窗口/RTT，故两窗口都取 4<<20-1，即 net/http 文档
// "小于 4MiB"允许的上界；并发流上限取主流站点的 128，而非 stdlib 默认的 250。
func TestBuildHTTPServerUploadFlowControl(t *testing.T) {
	srv := buildHTTPServer(&serverconfig.FileConfig{Server: serverconfig.ServerConfig{Port: 443}}, nil, http.NewServeMux(), 30*time.Second)
	require.NotNil(t, srv.HTTP2)
	require.Equal(t, (4<<20)-1, srv.HTTP2.MaxReceiveBufferPerStream,
		"per-stream upload window must be the documented upper bound (<4MiB)")
	require.Equal(t, (4<<20)-1, srv.HTTP2.MaxReceiveBufferPerConnection,
		"connection upload window is also the per-connection unconsumed-body bound")
	require.Equal(t, 128, srv.HTTP2.MaxConcurrentStreams,
		"per-connection stream limit should match mainstream servers, not Go's 250")
}

// TestBuildHTTPServerH2ConfigOverrides 固定 transport.h2_* 的覆盖语义：显式正值
// 覆盖默认值，0 表示"使用默认值"（文档化的字段语义，兜底在 buildHTTPServer）。
func TestBuildHTTPServerH2ConfigOverrides(t *testing.T) {
	cfg := &serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Port: 443},
		Transport: serverconfig.TransportConfig{
			H2RecvBufStream: 2 << 20,
			H2RecvBufConn:   8 << 20,
		},
	}
	srv := buildHTTPServer(cfg, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, 2<<20, srv.HTTP2.MaxReceiveBufferPerStream)
	require.Equal(t, 8<<20, srv.HTTP2.MaxReceiveBufferPerConnection)

	// 未配置（0 值）时回到共享常量：两处默认值不会各自漂移。
	cfg.Transport = serverconfig.TransportConfig{}
	srv = buildHTTPServer(cfg, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, config.HTTP2ServerReceiveBufferPerStream, srv.HTTP2.MaxReceiveBufferPerStream)
	require.Equal(t, config.HTTP2ServerReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerConnection)
	require.Equal(t, config.HTTP2ServerMaxConcurrentStreams, srv.HTTP2.MaxConcurrentStreams)
}

// TestBuildHTTPServerWarnsOnInvertedWindows 固定"连接级窗口应 ≥ 流级窗口"的可见性：
// 连接窗口是流级窗口的硬上限（每个字节同时扣减两个窗口），配得更小会压死单流在途
// 额度且不报错，故启动必须告警。只告警不纠正：压小窗口常是有意的内存收敛。
func TestBuildHTTPServerWarnsOnInvertedWindows(t *testing.T) {
	rec := captureServerLogs(t)

	// 两个窗口相等不是错误配置，不应有告警。
	buildHTTPServer(&serverconfig.FileConfig{Server: serverconfig.ServerConfig{Port: 443}}, nil, http.NewServeMux(), 30*time.Second)
	require.Empty(t, rec.warnings(), "equal windows must not warn")

	// 连接窗口 < 流级窗口：必须告警，并带上两个生效值供排查。
	cfg := &serverconfig.FileConfig{
		Server: serverconfig.ServerConfig{Port: 443},
		Transport: serverconfig.TransportConfig{
			H2RecvBufConn:   1 << 20,
			H2RecvBufStream: 4<<20 - 1,
		},
	}
	buildHTTPServer(cfg, nil, http.NewServeMux(), 30*time.Second)

	warns := rec.warnings()
	require.Len(t, warns, 1)
	require.Contains(t, warns[0].Message, "smaller than the per-stream window")

	attrs := map[string]string{}
	warns[0].Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	require.Equal(t, "1048576", attrs["h2_recv_buf_conn"])
	require.Equal(t, "4194303", attrs["h2_recv_buf_stream"])
}

// TestServerUploadFlowControlWindowsOnWire 守住服务端实际宣告的窗口与配置逐字节一致：
// 4<<20-1 一旦被 Go 校验会静默换成默认 1MB，吞吐掉回 1MB/RTT，因此必须用 Equal 而非下界。
func TestServerUploadFlowControlWindowsOnWire(t *testing.T) {
	built := buildHTTPServer(&serverconfig.FileConfig{Server: serverconfig.ServerConfig{Port: 443}}, nil, http.NewServeMux(), 30*time.Second)
	// 拷一份再交给 httptest：标准库只在装配连接时读该配置不回写，但共享指针暗含
	// 只读借用前提，复制后不再依赖它。
	http2Cfg := *built.HTTP2

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.EnableHTTP2 = true
	ts.Config.Protocols = &http.Protocols{}
	ts.Config.Protocols.SetHTTP2(true)
	ts.Config.HTTP2 = &http2Cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)

	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 测试专用的自签名证书
		NextProtos:         []string{"h2"},
	})
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)

	// 服务端读到客户端 preface 后立即刷新自己的 SETTINGS 与连接级 WINDOW_UPDATE。
	_, err = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	const (
		frameSettings     = 0x4
		frameWindowUpd    = 0x8
		settingMaxStreams = 0x3
		settingInitWin    = 0x4
		initialConnWin    = 65535 // RFC 7540 初始连接窗口
		maxFramesToRead   = 16
	)
	var streamWindow, maxStreams, connWindow = 0, 0, initialConnWin
	for range maxFramesToRead {
		var hdr [9]byte
		_, err := io.ReadFull(conn, hdr[:])
		require.NoError(t, err)
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

		payload := make([]byte, length)
		_, err = io.ReadFull(conn, payload)
		require.NoError(t, err)

		switch hdr[3] {
		case frameSettings:
			for len(payload) >= 6 {
				id := binary.BigEndian.Uint16(payload[:2])
				val := binary.BigEndian.Uint32(payload[2:6])
				payload = payload[6:]
				switch id {
				case settingInitWin:
					streamWindow = int(val)
				case settingMaxStreams:
					maxStreams = int(val)
				}
			}
		case frameWindowUpd:
			if streamID == 0 && len(payload) == 4 {
				connWindow += int(binary.BigEndian.Uint32(payload))
			}
		}
		if streamWindow > 0 && maxStreams > 0 && connWindow > initialConnWin {
			break
		}
	}

	// 与共享常量同源，生产配置不会各自漂移。
	require.Equal(t, config.HTTP2ServerReceiveBufferPerStream, streamWindow,
		"advertised per-stream upload window")
	require.Equal(t, config.HTTP2ServerReceiveBufferPerConnection, connWindow,
		"advertised connection upload window")
	require.Equal(t, config.HTTP2ServerMaxConcurrentStreams, maxStreams,
		"advertised per-connection concurrency limit")
	// 字面量固定文档允许的上界，防止常量被整体调小。
	require.Equal(t, (4<<20)-1, streamWindow)
	require.Equal(t, (4<<20)-1, connWindow)
	require.Equal(t, 128, maxStreams)
}

// TestServerUploadFlowControlInFlightPerStream 端到端守住流级窗口真的封住请求体：handler
// 故意不读请求体，在途字节数必须停止增长；配置取自 buildHTTPServer，字段接错会失败。
func TestServerUploadFlowControlInFlightPerStream(t *testing.T) {
	built := buildHTTPServer(&serverconfig.FileConfig{Server: serverconfig.ServerConfig{Port: 443}}, nil, http.NewServeMux(), 30*time.Second)
	http2Cfg := *built.HTTP2

	release := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读到 release 之前不碰 r.Body：能缓冲的字节数由窗口决定。
		<-release
	}))
	ts.EnableHTTP2 = true
	ts.Config.Protocols = &http.Protocols{}
	ts.Config.Protocols.SetHTTP2(true)
	ts.Config.HTTP2 = &http2Cfg
	ts.StartTLS()
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试专用的自签名证书
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.CloseWithError(io.ErrClosedPipe) })

	req, err := http.NewRequest(http.MethodPost, ts.URL+config.EndpointTCP, pr)
	require.NoError(t, err)
	go func() {
		// 结果无关紧要：handler 不读 body，请求会一直停在流控上。
		resp, err := tr.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	// 持续写 64KB 块直到被流控阻塞。
	chunk := make([]byte, 64<<10)
	var written atomic.Int64
	go func() {
		for {
			n, err := pw.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()

	// 在途量停止增长即额度耗尽（handler 不读就不会再有 WINDOW_UPDATE）。
	var inFlight int64
	stableSince := time.Now()
	deadline := time.Now().Add(20 * time.Second)
	for {
		time.Sleep(100 * time.Millisecond)
		cur := written.Load()
		if cur != inFlight {
			inFlight = cur
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight bytes never stabilized, written=%d", cur)
		}
	}

	// 在途上限取两个窗口的较小者：单流受流窗口限制，整条连接不会超过连接窗口。
	window := int64(min(http2Cfg.MaxReceiveBufferPerStream, http2Cfg.MaxReceiveBufferPerConnection))
	require.GreaterOrEqual(t, inFlight, window-256<<10,
		"client must be able to fill the configured per-stream window before backpressure")
	require.LessOrEqual(t, inFlight, window+512<<10,
		"in-flight data must be bounded by the configured per-stream window")
}

// TestLoopbackListenAddr 固定 server.listen → 内嵌 DERP 回环拨号地址的推导与拒绝规则：DERP 与
// 代理共用同一个 HTTPS 监听，因此"监听在回环上不可达"必须是启动错误，而不是等到节点连不上中继。
func TestLoopbackListenAddr(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   string
	}{
		{":443", "127.0.0.1:443"},
		{"0.0.0.0:8443", "127.0.0.1:8443"},
		// v6 监听（含通配）一律用 v6 回环拨号：v6 socket 一定能接受 ::1，
		// 而 127.0.0.1 在 bindv6only=1 的机器上会被拒。
		{"[::]:8443", "[::1]:8443"},
		{"127.0.0.1:9443", "127.0.0.1:9443"},
		// 只绑 v6 回环时不能拨 v4 回环：那个监听根本不接受 127.0.0.1。
		{"[::1]:9443", "[::1]:9443"},
	} {
		got, err := loopbackListenAddr(tc.listen)
		if err != nil {
			t.Errorf("loopbackListenAddr(%q): %v", tc.listen, err)
			continue
		}
		if got != tc.want {
			t.Errorf("loopbackListenAddr(%q) = %q, want %q", tc.listen, got, tc.want)
		}
	}

	for _, listen := range []string{"203.0.113.5:443", "example.com:443", "8443", ""} {
		if got, err := loopbackListenAddr(listen); err == nil {
			t.Errorf("loopbackListenAddr(%q) = %q, want an error: the embedded DERP could not be reached on loopback", listen, got)
		}
	}
}
