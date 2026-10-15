package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/server/config"
	"github.com/stretchr/testify/require"
)

// logRecorder 捕获包级日志器的记录，用于断言"配置不当会告警"这类行为。
// server 包的用例不并行，因此替换包级日志器是安全的（与 transport/http2、
// server/handler 的用例同一手法）。
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

func TestCertmagicStoragePathForExecutable(t *testing.T) {
	exe := filepath.Join("tmp", "easyss", "easyss-server")
	require.Equal(t, filepath.Join("tmp", "easyss", "certmagic"), certmagicStoragePathForExecutable(exe))
}

func TestNewTransportProtocolsValidation(t *testing.T) {
	require.NoError(t, mustNewServer(t, nil))
	require.NoError(t, mustNewServer(t, []string{"h2"}))
	require.Error(t, mustNewServer(t, []string{"h3"}))
	require.Error(t, mustNewServer(t, []string{"h2", "h3"}))
}

func mustNewServer(t *testing.T, protocols []string) error {
	t.Helper()
	_, err := New(&config.FileConfig{
		Transport: config.TransportConfig{Protocols: protocols},
	})
	return err
}

func TestShouldRetryFreshCertificate(t *testing.T) {
	require.True(t, shouldRetryFreshCertificate(errString("Could not validate ARI 'replaces' field")))
	require.True(t, shouldRetryFreshCertificate(errString("Requested certificate was not found")))
	require.False(t, shouldRetryFreshCertificate(errString("dial tcp: i/o timeout")))
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

// TestCertmagicAcceptsPublicIPSubject 是 IP-only 模式对依赖的守卫测试：certmagic
// 用一张硬编码的表判断"某个公网 CA 是否支持 IP 证书"，而这个功能完全依赖那张表里
// Let's Encrypt 是 true。它不联网（显式设置 Email，PreCheck 因此既不读存储也不
// 向用户提问），只在升级 certmagic 或改动 CA 时让"IP 证书不再被支持"立刻变红。
//
// 同时钉住私有地址确实被预检拒绝：server/config.validateTLS 的判据比它更严（还
// 覆盖 CGNAT/TEST-NET 等段），但两者对私有地址必须一致，否则配置层那道闸就成了
// 唯一一道。
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

	// 创建模拟 certmagic 的目录结构：
	// certmagic/acme/acme-v02.api.letsencrypt.org-directory/users/old@example.com/
	// certmagic/acme/acme-v02.api.letsencrypt.org-directory/users/new@example.com/
	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	oldEmailDir := filepath.Join(usersPath, "old@example.com")
	newEmailDir := filepath.Join(usersPath, "new@example.com")

	require.NoError(t, os.MkdirAll(oldEmailDir, 0700))
	require.NoError(t, os.MkdirAll(newEmailDir, 0700))

	// 确保旧邮箱的修改时间更早
	oldTime := time.Now().Add(-1 * time.Hour)
	require.NoError(t, os.Chtimes(oldEmailDir, oldTime, oldTime))

	result := findExistingACMEEmail(storagePath)
	require.Equal(t, "old@example.com", result)
}

func TestFindExistingACMEEmail_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	// 完全没有 acme 目录
	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestFindExistingACMEEmail_NoUsers(t *testing.T) {
	tmpDir := t.TempDir()

	// acme 目录存在但没有 users 子目录
	acmePath := filepath.Join(tmpDir, "acme", "some-ca")
	require.NoError(t, os.MkdirAll(acmePath, 0700))

	result := findExistingACMEEmail(tmpDir)
	require.Equal(t, "", result)
}

func TestResolveEmail_Configured(t *testing.T) {
	s := &Server{
		cfg: &config.FileConfig{
			Server: config.ServerConfig{Email: "user@example.com"},
		},
	}
	s.resolveEmail(t.TempDir())
	require.Equal(t, "user@example.com", s.cfg.Server.Email)
}

func TestResolveEmail_Reuse(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "certmagic")

	// 在磁盘上创建已存在的邮箱
	usersPath := filepath.Join(storagePath, "acme", "acme-v02.api.letsencrypt.org-directory", "users")
	existingEmail := "reused@example.com"
	require.NoError(t, os.MkdirAll(filepath.Join(usersPath, existingEmail), 0700))

	s := &Server{
		cfg: &config.FileConfig{
			Server: config.ServerConfig{Email: ""}, // 未配置
		},
	}
	s.resolveEmail(storagePath)
	require.Equal(t, existingEmail, s.cfg.Server.Email)
}

func TestResolveEmail_Generated(t *testing.T) {
	s := &Server{
		cfg: &config.FileConfig{
			Server: config.ServerConfig{Email: ""},
		},
	}
	s.resolveEmail(t.TempDir())

	matched, err := regexp.MatchString(`^admin_[0-9a-f]{16}@gmail\.com$`, s.cfg.Server.Email)
	require.NoError(t, err)
	require.True(t, matched, "unexpected generated email format: %s", s.cfg.Server.Email)
}

// TestBuildHTTPServerUploadFlowControl 用字面量固定上传侧的 HTTP/2 参数
// （而不是直接引用常量本身，这样缩小常量的回归同样会让本测试失败）：
// 单条上传流的吞吐 ≈ 窗口/RTT，两个窗口都取 net/http 文档允许的上界
// （文档要求"小于 4MiB"，因此最大合法值就是 4<<20-1；4<<20 恰好越界，而改前的
// 连接级窗口正是这个越界值）。并发流上限取实测主流站点的 128，而不是 Go stdlib
// 默认的 250。
func TestBuildHTTPServerUploadFlowControl(t *testing.T) {
	srv := buildHTTPServer(&config.FileConfig{Server: config.ServerConfig{Listen: ":443"}}, nil, http.NewServeMux(), 30*time.Second)
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
	cfg := &config.FileConfig{
		Server: config.ServerConfig{Listen: ":443"},
		Transport: config.TransportConfig{
			H2RecvBufStream:        2 << 20,
			H2RecvBufConn:          8 << 20,
			H2MaxConcurrentStreams: 64,
		},
	}
	srv := buildHTTPServer(cfg, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, 2<<20, srv.HTTP2.MaxReceiveBufferPerStream)
	require.Equal(t, 8<<20, srv.HTTP2.MaxReceiveBufferPerConnection)
	require.Equal(t, 64, srv.HTTP2.MaxConcurrentStreams)

	// 未配置（0 值）时回到共享常量：两处默认值不会各自漂移。
	cfg.Transport = config.TransportConfig{}
	srv = buildHTTPServer(cfg, nil, http.NewServeMux(), 30*time.Second)
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerStream, srv.HTTP2.MaxReceiveBufferPerStream)
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerConnection)
	require.Equal(t, sharedconfig.HTTP2ServerMaxConcurrentStreams, srv.HTTP2.MaxConcurrentStreams)
}

// TestBuildHTTPServerWarnsOnInvertedWindows 固定"连接级窗口应 ≥ 流级窗口"这条
// 不变量的可见性：连接窗口是流级窗口的硬上限（每个字节都要同时扣减两个窗口），
// 把它配得更小时单条流的在途额度由它决定——那正是"上传速度上不去"的一类配置，
// 而且不会以任何其他方式暴露出来，所以启动时必须告警。只告警不纠正：压小连接
// 窗口往往是有意的内存收敛，替运维改大反而违背其意图。
func TestBuildHTTPServerWarnsOnInvertedWindows(t *testing.T) {
	rec := captureServerLogs(t)

	// 默认（连接窗口 == 流级窗口）不是错误配置，不应有告警。
	buildHTTPServer(&config.FileConfig{Server: config.ServerConfig{Listen: ":443"}}, nil, http.NewServeMux(), 30*time.Second)
	require.Empty(t, rec.warnings(), "equal windows must not warn")

	// 连接窗口 < 流级窗口：必须告警，并带上两个生效值供排查。
	cfg := &config.FileConfig{
		Server: config.ServerConfig{Listen: ":443"},
		Transport: config.TransportConfig{
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

// TestServerUploadFlowControlWindowsOnWire 验证服务端**实际宣告**的上行参数与
// buildHTTPServer 组装的配置逐字节一致：SETTINGS_INITIAL_WINDOW_SIZE 携带流级
// 窗口、SETTINGS_MAX_CONCURRENT_STREAMS 携带每连接并发流上限，连接级
// WINDOW_UPDATE 在 RFC 7540 初始 65535 字节的基础上补齐连接窗口。标准库服务端会
// 排队其 SETTINGS，并在客户端 preface 一到就立即刷新，因此 preface 之后这些帧
// 立即可读。
//
// 断言刻意用 Equal 而不是">= 下界"：net/http 文档把这两个窗口字段的合法值写在
// "小于 4MiB"，而实现当前并不校验它（内部钳制区间是 [64KiB, MaxInt32]）。一旦
// 某个 Go 版本开始校验，我们的值会被**静默**换成默认值 1MB——上传吞吐直接掉回
// 1MB/RTT。那正是本测试要拦住的回归。
func TestServerUploadFlowControlWindowsOnWire(t *testing.T) {
	built := buildHTTPServer(&config.FileConfig{Server: config.ServerConfig{Listen: ":443"}}, nil, http.NewServeMux(), 30*time.Second)
	// 拷一份再交给 httptest：标准库只在装配连接时读取该配置
	// （ServeConn → configFromServer），不会回写，但把同一个指针既交给它又留在
	// 测试局部变量里属于隐式的只读借用前提，复制后就不再依赖那一条。
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

	// 发送 HTTP/2 客户端 preface：服务端一旦读到它，就会刷新自己的 SETTINGS
	// 和连接级 WINDOW_UPDATE。
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

	// 与常量同源（生产配置与文档不会各自漂移）……
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerStream, streamWindow,
		"advertised per-stream upload window")
	require.Equal(t, sharedconfig.HTTP2ServerReceiveBufferPerConnection, connWindow,
		"advertised connection upload window")
	require.Equal(t, sharedconfig.HTTP2ServerMaxConcurrentStreams, maxStreams,
		"advertised per-connection concurrency limit")
	// ……并且就是文档允许的上界（写死字面量，防止常量被整体调小）。
	require.Equal(t, (4<<20)-1, streamWindow)
	require.Equal(t, (4<<20)-1, connWindow)
	require.Equal(t, 128, maxStreams)
}

// TestServerUploadFlowControlInFlightPerStream 端到端固定**流级**窗口的语义：
// handler 故意不读请求体，客户端能塞进去的在途字节数就被流控窗口封顶。这条不变式
// 正是上传吞吐的来源（吞吐 ≈ 窗口/RTT），也是本次改动唯一会改变的量。
//
// 服务端配置取自 buildHTTPServer 而不是在这里手抄常量：这样覆盖条件写反、字段接错
// 这类接线错误同样会被本用例抓住（与 TestServerUploadFlowControlWindowsOnWire
// 一致）。
//
// 两侧都留余量：下界排除"窗口其实还是默认 1MB"这类静默回落，上界排除"窗口被设成
// 不受限（甚至无限）"这类错误。测量依据"在途量停止增长"而不是计时，因此在 CI 上
// 不抖动；余量覆盖客户端管道/h2 写入侧一拍（最多两个 64KB 块）的交接。
func TestServerUploadFlowControlInFlightPerStream(t *testing.T) {
	built := buildHTTPServer(&config.FileConfig{Server: config.ServerConfig{Listen: ":443"}}, nil, http.NewServeMux(), 30*time.Second)
	http2Cfg := *built.HTTP2

	release := make(chan struct{})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读到 release 之前不碰 r.Body：服务端能缓冲的字节数由窗口决定。
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

	req, err := http.NewRequest(http.MethodPost, ts.URL+sharedconfig.EndpointTCP, pr)
	require.NoError(t, err)
	go func() {
		// 结果无关紧要：只要 handler 不读 body，这个请求就会一直停在流控上。
		resp, err := tr.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	// 持续写 64KB 块，直到因流控阻塞。
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

	// 在途量停止增长即代表额度耗尽（handler 不读 → 不会再有 WINDOW_UPDATE）。
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

	// 在途上限是流级与连接级窗口的较小者：单流能占多少受流窗口限制，但整条连接
	// 的信用额度（连接窗口）无论如何不会超过。取生效配置（而不是常量）描述这条
	// 不变式，字段接错时本用例同样会失败。
	window := int64(min(http2Cfg.MaxReceiveBufferPerStream, http2Cfg.MaxReceiveBufferPerConnection))
	require.GreaterOrEqual(t, inFlight, window-256<<10,
		"client must be able to fill the configured per-stream window before backpressure")
	require.LessOrEqual(t, inFlight, window+512<<10,
		"in-flight data must be bounded by the configured per-stream window")
}
