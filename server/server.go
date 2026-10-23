package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	serverconfig "github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/vpn"
)

type Server struct {
	cfg        *serverconfig.FileConfig
	httpServer *http.Server
	mux        *http.ServeMux
	certCache  *certmagic.Cache
	derp       *vpn.DERPServer
	// mesh 是同 region 内其他内嵌 DERP 的互联（server.vpn.mesh_*）。未配置时为
	// nil，此时服务端与既有版本逐字节一致。meshCtx/meshCancel 约束它的生命周期：
	// Shutdown 先取消再关闭，确保不会再登记新的转发映射。
	mesh       *vpn.Mesh
	meshCtx    context.Context
	meshCancel context.CancelFunc
	statsDone  chan struct{}
	statsOnce  sync.Once
}

// acmeProfileShortLived 只为 IP 标识符而设：LE 的 IP 地址证书必须是短生命周期证书，
// shortlived 是唯一允许 ip 标识符的 profile，名称写错会在启动期报 unknown profile name。
const acmeProfileShortLived = "shortlived"

// New 自己校验一次：测试与嵌入式调用会直接手搓 FileConfig，只靠配置加载路径校验等于留一条
// 绕过口子。Validate 是纯内存检查且幂等。
func New(cfg *serverconfig.FileConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) initTLS() (*tls.Config, error) {
	cfg := s.cfg
	srvCfg := cfg.Server

	if cfg.UsesManualCertificate() {
		cert, err := tls.LoadX509KeyPair(srvCfg.CertPath, srvCfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   config.NextProtos,
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	storagePath, err := certmagicStoragePath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("create certmagic storage: %w", err)
	}

	s.resolveEmail(storagePath)

	storage := &certmagic.FileStorage{Path: storagePath}

	tlsConfig, cache, err := s.manageCert(storage, false)
	if err != nil && shouldRetryFreshCertificate(err) {
		if cache != nil {
			cache.Stop()
		}
		_ = cleanCertmagicDomainAssets(context.Background(), storage, srvCfg.Host)
		tlsConfig, cache, err = s.manageCert(storage, true)
	}
	if err != nil {
		if cache != nil {
			cache.Stop()
		}
		return nil, fmt.Errorf("certmagic: %w", err)
	}

	s.certCache = cache
	tlsConfig.NextProtos = append(slices.Clone(config.NextProtos), tlsConfig.NextProtos...)
	return tlsConfig, nil
}

func (s *Server) manageCert(storage certmagic.Storage, disableARI bool) (*tls.Config, *certmagic.Cache, error) {
	var cmCfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cmCfg, nil
		},
	})

	cmCfg = certmagic.New(cache, certmagic.Config{
		Storage:    storage,
		DisableARI: disableARI,
	})

	acmeCfg := certmagic.DefaultACME
	acmeCfg.Agreed = true
	acmeCfg.Email = s.cfg.Server.Email
	acmeCfg.DisableHTTPChallenge = true
	// IP 标识符必须显式请求短生命周期 profile：LE 对 ip 标识符会自动选它，但"IP 证书只能是
	// 短生命周期证书"是这个模式的硬约束，写在请求里才不依赖服务端的自动选择。
	if s.cfg.ACMESubjectIsIP() {
		acmeCfg.Profile = acmeProfileShortLived
	}
	cmCfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cmCfg, acmeCfg)}

	tlsConfig := cmCfg.TLSConfig()
	err := cmCfg.ManageSync(context.Background(), []string{s.cfg.Server.Host})
	if err != nil {
		return nil, cache, err
	}
	return tlsConfig, cache, nil
}

func (s *Server) resolveEmail(storagePath string) {
	if s.cfg.Server.Email != "" {
		return
	}
	if existing := findExistingACMEEmail(storagePath); existing != "" {
		s.cfg.Server.Email = existing
		log.Info("[SERVER] reused existing ACME email", "email", existing)
		return
	}
	s.cfg.Server.Email = randomEmail()
	log.Info("[SERVER] generated random ACME email", "email", s.cfg.Server.Email)
}

func (s *Server) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			snap := stats.Collect()
			log.Info("[SERVER_STATS]",
				"uptime", snap.Uptime().Round(time.Second),
				"tx", stats.HumanBytes(snap.BytesSent),
				"rx", stats.HumanBytes(snap.BytesRecv),
				"tcp", snap.ServerTCPStreams,
				"udp", snap.ServerUDPStreams,
				"icmp", snap.ServerICMPStreams,
				"hserr", snap.ServerHandshakeErrors,
				"scancel", snap.ServerStreamCancels,
				"fallback", snap.ServerFallbackPages,
				"probe", snap.ServerProbes,
				"padding", stats.HumanBytes(snap.PaddingBytes),
				"records", snap.RecordsWritten,
			)
		case <-s.statsDone:
			return
		}
	}
}

func certmagicStoragePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}
	if realExe, err := filepath.EvalSymlinks(exe); err == nil {
		exe = realExe
	}
	return certmagicStoragePathForExecutable(exe), nil
}

func certmagicStoragePathForExecutable(exe string) string {
	return filepath.Join(filepath.Dir(exe), "certmagic")
}

func findExistingACMEEmail(storagePath string) string {
	acmePath := filepath.Join(storagePath, "acme")
	caDirs, err := os.ReadDir(acmePath)
	if err != nil {
		return ""
	}

	var earliestEmail string
	var earliestTime time.Time
	for _, caDir := range caDirs {
		if !caDir.IsDir() {
			continue
		}
		usersPath := filepath.Join(acmePath, caDir.Name(), "users")
		emailDirs, err := os.ReadDir(usersPath)
		if err != nil {
			continue
		}
		for _, emailDir := range emailDirs {
			if !emailDir.IsDir() {
				continue
			}
			info, err := emailDir.Info()
			if err != nil {
				continue
			}
			if earliestEmail == "" || info.ModTime().Before(earliestTime) {
				earliestTime = info.ModTime()
				earliestEmail = emailDir.Name()
			}
		}
	}
	return earliestEmail
}

func randomEmail() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "admin_" + hex.EncodeToString(b) + "@gmail.com"
}

func shouldRetryFreshCertificate(err error) bool {
	if err == nil {
		return false
	}
	// 按类型分类 ACME 失败：detail 文本只在 Problem 类型本身不足以区分时兜底。
	if problem, ok := errors.AsType[acme.Problem](err); ok {
		// 404 在 ACME 语义下基本只来自 ARI（certID 不存在）。它比 detail 文本略宽，
		// 但重签只发生在启动阶段，接受这个已知的宽判据。
		if problem.Type == acme.ProblemTypeAlreadyReplaced ||
			problem.Status == http.StatusNotFound {
			return true
		}
		detail := strings.ToLower(problem.Detail)
		return strings.Contains(detail, "replaces field") ||
			strings.Contains(detail, "could not validate ari") ||
			strings.Contains(detail, "requested certificate was not found")
	}
	// 兼容没有 acme.Problem 包装的路径（上层可能把错误文本重新包装）。
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "replaces field") ||
		strings.Contains(msg, "could not validate ari") ||
		strings.Contains(msg, "requested certificate was not found")
}

func cleanCertmagicDomainAssets(ctx context.Context, storage certmagic.Storage, domain string) error {
	issuerKey := (&certmagic.ACMEIssuer{CA: certmagic.DefaultACME.CA}).IssuerKey()
	keys := []string{
		certmagic.StorageKeys.SiteCert(issuerKey, domain),
		certmagic.StorageKeys.SitePrivateKey(issuerKey, domain),
		certmagic.StorageKeys.SiteMeta(issuerKey, domain),
		certmagic.StorageKeys.CertsSitePrefix(issuerKey, domain),
	}
	var lastErr error
	for _, key := range keys {
		if err := storage.Delete(ctx, key); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (s *Server) Start() error {
	cfg := s.cfg
	srvCfg := cfg.Server
	// 这里再算一次（幂等）是为了覆盖不经过配置加载的调用方，启动日志与后续派生看到同一个值。
	timeout := config.TimeoutDuration(cfg.Timeout)
	log.Info("[SERVER] starting", "listen", srvCfg.ListenAddr(), "host", srvCfg.Host, "timeout", int(timeout.Seconds()))

	tlsConfig, err := s.initTLS()
	if err != nil {
		log.Error("[SERVER] init TLS failed", "err", err)
		return err
	}
	if cfg.UsesManualCertificate() {
		log.Info("[SERVER] TLS mode: cert files", "cert", srvCfg.CertPath, "key", srvCfg.KeyPath)
	} else if cfg.ACMESubjectIsIP() {
		// IP-only 模式：LE 直接为这个公网 IPv4 签发短生命周期证书，只能用 tls-alpn-01 验证，
		// 因此公网 443 在首次签发与每次续期时都必须可达。
		log.Info("[SERVER] TLS mode: certmagic (Let's Encrypt IP certificate)",
			"subject", srvCfg.Host, "email", srvCfg.Email, "profile", acmeProfileShortLived,
			"challenge", "tls-alpn-01", "acme_requires", "inbound tcp/443 from the internet")
	} else {
		log.Info("[SERVER] TLS mode: certmagic (Let's Encrypt)", "host", srvCfg.Host, "email", srvCfg.Email)
	}

	timeouts := config.NewTimeouts(timeout)

	fallback, err := handler.NewFallback(handler.FallbackConfig{
		Target:       cfg.Fallback.Target,
		PreserveHost: cfg.Fallback.PreserveHost,
		CDNDomains:   cfg.Fallback.CDNDomains,
	})
	if err != nil {
		return fmt.Errorf("fallback target: %w", err)
	}
	if cfg.Fallback.Target != "" {
		log.Info("[SERVER] fallback target configured", "target", cfg.Fallback.Target, "preserve_host", cfg.Fallback.PreserveHost, "cdn_domains", cfg.Fallback.CDNDomains)
	}

	masterKey, err := crypto.DeriveMasterKey(srvCfg.Password)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	np, err := nextproxy.New(cfg.NextProxy.URL, cfg.NextProxy.EnableUDP, cfg.NextProxy.AllHost)
	if err != nil {
		log.Error("[SERVER] next proxy init failed", "err", err)
		return fmt.Errorf("next proxy: %w", err)
	}
	if np != nil {
		if err := np.LoadProxyFile(cfg.NextProxy.NextProxyFile); err != nil {
			log.Error("[SERVER] next proxy load file failed", "err", err)
			return fmt.Errorf("next proxy load file: %w", err)
		}
		np.SetDialTimeout(timeouts.Dial)
		log.Info("[SERVER] next proxy configured", "url", cfg.NextProxy.URL, "udp", cfg.NextProxy.EnableUDP, "all_host", cfg.NextProxy.AllHost)
	}

	// 内嵌 DERP：它只对来自回环的请求提供服务（见 vpn.NewDERPMount），而节点的
	// DERP 连接经 easyss 隧道到达这里，握手目标正是本服务端对外通告的 DERP 地址。
	// 因此要先把该地址与它的回环映射算出来，交给 proxyHandler（见
	// handler.ProxyHandlerConfig.LocalDERPAddr 与 dialTarget）。
	var derpAddr, derpLoopback string
	if srvCfg.VPN.Enabled {
		if derpAddr, err = cfg.ResolveDERPAddr(); err != nil {
			return err
		}
		if derpLoopback, err = loopbackListenAddr(srvCfg.ListenAddr()); err != nil {
			return fmt.Errorf("server.vpn requires a loopback-reachable listen address: %w", err)
		}
	}

	proxyHandler := handler.NewProxyHandler(handler.ProxyHandlerConfig{
		MasterKey:         masterKey,
		AllowedMethods:    srvCfg.GetAllowedMethods(),
		Timeouts:          timeouts,
		Shaper:            cfg.Shaper,
		NextProxy:         np,
		Fallback:          fallback,
		LocalDERPAddr:     derpAddr,
		LocalDERPLoopback: derpLoopback,
	})

	probePayload := make([]byte, config.ProbePayloadSize)
	if _, err := io.ReadFull(rand.Reader, probePayload); err != nil {
		return fmt.Errorf("generate probe payload: %w", err)
	}
	probeHandler, err := handler.NewProbeHandler(masterKey, probePayload, fallback)
	if err != nil {
		return fmt.Errorf("probe handler: %w", err)
	}

	// 顶层处理器：启用 VPN 时把真正的 DERP 流量分流给内嵌中继，其余路径一律走
	// 伪装页面。分流的理由、以及为什么必须在 `/` 的兜底处理器内部做，见
	// vpn.NewDERPMount。
	var root http.Handler = http.HandlerFunc(fallback.Serve)
	if srvCfg.VPN.Enabled {
		derpSrv, err := s.startDERP(derpAddr, srvCfg.VPN.DERPSendQueueDepth)
		if err != nil {
			return err
		}
		s.derp = derpSrv
		root = vpn.NewDERPMount(derpSrv.Handler(), fallback)

		// mesh 必须在 DERP 开始服务之前落位（derpserver 要求 SetMeshKey 早于服务），
		// 而 mesh 客户端本身是异步拨号 + 重试的，因此这里的顺序只影响"第一个同伴
		// 何时被认出来"，不影响正确性。
		if srvCfg.VPN.MeshKey != "" {
			s.meshCtx, s.meshCancel = context.WithCancel(context.Background())
			if err := s.startDERPMesh(cfg, derpSrv, np, timeouts.Dial); err != nil {
				return err
			}
		}
	}

	s.mux = http.NewServeMux()
	s.mux.Handle("/", root)
	s.mux.Handle(config.EndpointTCP, proxyHandler)
	s.mux.Handle(config.EndpointUDP, proxyHandler)
	s.mux.Handle(config.EndpointICMP, proxyHandler)
	s.mux.Handle(config.EndpointProbe, probeHandler)

	s.httpServer = buildHTTPServer(cfg, tlsConfig, s.mux, timeout)

	routes := []string{"/", config.EndpointTCP, config.EndpointUDP, config.EndpointICMP, config.EndpointProbe}
	if s.derp != nil {
		routes = append(routes, config.DefaultVPNDERPPath)
	}
	// 打进生效的 HTTP/2 参数：上传速度上不去时，第一件事是确认服务端给了多大的窗口与并发流。
	log.Info("[SERVER] listening",
		"addr", srvCfg.ListenAddr(),
		"routes", routes,
		"h2_max_frame_size", s.httpServer.HTTP2.MaxReadFrameSize,
		"h2_recv_buf_stream", s.httpServer.HTTP2.MaxReceiveBufferPerStream,
		"h2_recv_buf_conn", s.httpServer.HTTP2.MaxReceiveBufferPerConnection,
		"h2_max_concurrent_streams", s.httpServer.HTTP2.MaxConcurrentStreams)
	s.statsDone = make(chan struct{})
	go s.statsLoop()
	return s.httpServer.ListenAndServeTLS("", "")
}

// loopbackListenAddr 由 server.listen 推导内嵌 DERP 的本机回环拨号地址
// （127.0.0.1:<listen 端口>）。
//
// DERP 与代理共用同一个 HTTPS 监听，节点经 easyss 隧道送来的 DERP 连接会在这里被改拨
// 回环（见 handler.dialTarget）。该监听在回环上必须可达：只绑了某一个非回环地址时它是
// 配置错误，必须在启动时明确拒绝，而不是等到节点连不上才暴露。
func loopbackListenAddr(listen string) (string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid server.listen %q: %w", listen, err)
	}
	loopback := "127.0.0.1"
	if host != "" {
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil || (!ip.IsUnspecified() && !ip.IsLoopback()) {
			return "", fmt.Errorf("server.listen %q is bound to %s, so the embedded DERP cannot be reached on loopback; "+
				"listen on a wildcard address (e.g. \":443\") or on a loopback address", listen, host)
		}
		// 地址族必须跟着监听走：只绑在 [::1] 上的监听不会接受 127.0.0.1 的连接。
		if ip.Is6() {
			loopback = "::1"
		}
	}
	port, err := config.PortFromListen(listen)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(loopback, strconv.Itoa(port)), nil
}

// startDERP 装载内嵌 DERP 中继，返回可直接挂到根处理器上的实例。addr 是它对外通告的
// host:port（由 ResolveDERPAddr 推导）。sendQueueDepth 来自 server.vpn.derp_send_queue_depth，
// 归一化与默认值只在 config.NormalizeDERPSendQueueDepth 里定义一次。
func (s *Server) startDERP(addr string, sendQueueDepth int) (*vpn.DERPServer, error) {
	derpKey, err := vpn.LoadOrCreateKey(vpn.DERPKeyPath())
	if err != nil {
		log.Error("[SERVER] load derp key failed", "err", err)
		return nil, err
	}
	derpSrv := vpn.NewDERPServer(derpKey, sendQueueDepth)
	log.Info("[SERVER] embedded DERP enabled",
		"derp_addr", addr,
		"path", config.DefaultVPNDERPPath,
		"derp_public_key", derpSrv.PublicKey().String(),
		"derp_send_queue_depth", derpSrv.SendQueueDepth(),
		"key_file", vpn.DERPKeyPath())
	return derpSrv, nil
}

// buildHTTPServer 的 HTTP/2 参数按上传吞吐量定尺寸：流级接收窗口决定单条上传流的在途数据量
// （吞吐 ≈ 窗口/RTT），连接级窗口是每连接上界。这里只保留 0 值兜底。
func buildHTTPServer(cfg *serverconfig.FileConfig, tlsConfig *tls.Config, mux *http.ServeMux, timeout time.Duration) *http.Server {
	http2Cfg := &http.HTTP2Config{
		MaxReadFrameSize:              effectiveH2(cfg.Transport.H2MaxFrameSize, config.HTTP2ServerMaxReadFrameSize),
		MaxReceiveBufferPerConnection: effectiveH2(cfg.Transport.H2RecvBufConn, config.HTTP2ServerReceiveBufferPerConnection),
		MaxReceiveBufferPerStream:     effectiveH2(cfg.Transport.H2RecvBufStream, config.HTTP2ServerReceiveBufferPerStream),
		MaxConcurrentStreams:          config.HTTP2ServerMaxConcurrentStreams,
	}

	// 连接级窗口同时是流级窗口的硬上限：配得比流级窗口小，单条流的在途额度就由它决定，
	// 且不会以其他方式暴露。只告警不纠正：压小连接窗口往往是有意的内存收敛。
	if http2Cfg.MaxReceiveBufferPerConnection < http2Cfg.MaxReceiveBufferPerStream {
		log.Warn("[SERVER] h2 connection receive window is smaller than the per-stream window: the effective per-stream in-flight limit is the connection window",
			"h2_recv_buf_conn", http2Cfg.MaxReceiveBufferPerConnection,
			"h2_recv_buf_stream", http2Cfg.MaxReceiveBufferPerStream)
	}

	srv := &http.Server{
		Addr:              cfg.Server.ListenAddr(),
		TLSConfig:         tlsConfig,
		Handler:           mux,
		ErrorLog:          stdErrorLog(),
		Protocols:         &http.Protocols{},
		HTTP2:             http2Cfg,
		IdleTimeout:       8 * timeout,
		ReadHeaderTimeout: min(timeout/2, 10*time.Second),
	}
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetHTTP2(true)
	return srv
}

// 越界值由 config.LoadConfig 拒绝；0 值兜底让绕过配置加载的调用方拿到默认值而不是 0。
func effectiveH2(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Info("[SERVER] shutting down")

	s.statsOnce.Do(func() {
		if s.statsDone != nil {
			close(s.statsDone)
		}
	})

	if s.certCache != nil {
		s.certCache.Stop()
		s.certCache = nil
	}

	var err error
	// 先停 mesh 再停 HTTP：mesh 的订阅循环会往中继里登记转发映射，先取消它就不会
	// 在收尾过程中出现新的映射（关闭顺序与 DERP 本身的收尾一致，见下）。
	if s.meshCancel != nil {
		s.meshCancel()
		s.meshCancel = nil
	}
	if s.mesh != nil {
		if cerr := s.mesh.Close(); cerr != nil && err == nil {
			err = cerr
		}
		s.mesh = nil
	}
	if s.httpServer != nil {
		err = s.httpServer.Shutdown(ctx)
	}
	// 先停 HTTP 再收中继：Shutdown 不会等待已被 Hijack 的连接（DERP 的连接都
	// 是 Hijack 走的），因此这里必须显式收尾，否则中继的收发 goroutine 会一直
	// 留在进程里。
	if s.derp != nil {
		if cerr := s.derp.Close(); cerr != nil && err == nil {
			err = cerr
		}
		s.derp = nil
	}
	return err
}

// stdErrorLog 把 http.Server/HTTP2 的内部日志（连接级错误、PING 超时、TLS 握手错误）转接到
// easyss 的 slog 日志器。
func stdErrorLog() *stdlog.Logger {
	return stdlog.New(slogErrorWriter{}, "", 0)
}

type slogErrorWriter struct{}

func (slogErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		log.Error("[HTTP2]", "detail", msg)
	}
	return len(p), nil
}
