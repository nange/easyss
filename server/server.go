package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/vpn"
)

type Server struct {
	cfg        *config.FileConfig
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

func New(cfg *config.FileConfig) (*Server, error) {
	for _, p := range cfg.Transport.Protocols {
		if p != "h2" {
			return nil, fmt.Errorf("unsupported transport protocol %q (only h2 is supported)", p)
		}
	}

	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) initTLS() (*tls.Config, error) {
	cfg := s.cfg
	srvCfg := cfg.Server

	if srvCfg.CertPath != "" && srvCfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(srvCfg.CertPath, srvCfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   sharedconfig.NextProtos,
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
		_ = cleanCertmagicDomainAssets(context.Background(), storage, srvCfg.Domain)
		tlsConfig, cache, err = s.manageCert(storage, true)
	}
	if err != nil {
		if cache != nil {
			cache.Stop()
		}
		return nil, fmt.Errorf("certmagic: %w", err)
	}

	s.certCache = cache
	tlsConfig.NextProtos = append(slices.Clone(sharedconfig.NextProtos), tlsConfig.NextProtos...)
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
	cmCfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cmCfg, acmeCfg)}

	tlsConfig := cmCfg.TLSConfig()
	err := cmCfg.ManageSync(context.Background(), []string{s.cfg.Server.Domain})
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
	// 基础超时派生出流空闲、UDP 空闲、拨号与 h2 连接空闲。经 config.LoadConfig
	// 加载的配置已在 applyDefaults 里归一化并写回，这里再算一次（幂等）是为了
	// 覆盖不经过配置加载的调用方（测试、嵌入式使用会直接手搓 FileConfig），
	// 因此启动日志与后续全部派生始终看到同一个值（见 sharedconfig.NormalizeTimeout）。
	timeout := sharedconfig.TimeoutDuration(cfg.Timeout)
	log.Info("[SERVER] starting", "listen", srvCfg.Listen, "domain", srvCfg.Domain, "timeout", int(timeout.Seconds()))

	tlsConfig, err := s.initTLS()
	if err != nil {
		log.Error("[SERVER] init TLS failed", "err", err)
		return err
	}
	if srvCfg.CertPath != "" && srvCfg.KeyPath != "" {
		log.Info("[SERVER] TLS mode: cert files", "cert", srvCfg.CertPath, "key", srvCfg.KeyPath)
	} else {
		log.Info("[SERVER] TLS mode: certmagic (Let's Encrypt)", "domain", srvCfg.Domain, "email", srvCfg.Email)
	}

	timeouts := sharedconfig.NewTimeouts(timeout)

	// 构造本次部署唯一的回退实例：模式配置与部署级身份都在这里一次性确定，
	// 随后由各个 handler 共享。构造失败会直接让服务器启动失败，不会留下
	// 部分改写的可见状态。
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
		if derpLoopback, err = loopbackListenAddr(srvCfg.Listen); err != nil {
			return fmt.Errorf("server.vpn requires a loopback-reachable listen address: %w", err)
		}
	}

	proxyHandler := handler.NewProxyHandler(handler.ProxyHandlerConfig{
		MasterKey:      masterKey,
		AllowedMethods: srvCfg.GetAllowedMethods(),
		Timeouts:       timeouts,
		Shaper: shaper.Config{
			BatchWindowMS: cfg.Shaper.BatchWindowMS,
			Cover: shaper.CoverConfig{
				BudgetRatio: cfg.Shaper.CoverBudgetRatio,
				BudgetCap:   cfg.Shaper.CoverBudgetCap,
			},
		},
		NextProxy:         np,
		Fallback:          fallback,
		LocalDERPAddr:     derpAddr,
		LocalDERPLoopback: derpLoopback,
	})

	probePayload := make([]byte, sharedconfig.ProbePayloadSize)
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
		derpSrv, err := s.startDERP(derpAddr)
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
	s.mux.Handle(sharedconfig.EndpointTCP, proxyHandler)
	s.mux.Handle(sharedconfig.EndpointUDP, proxyHandler)
	s.mux.Handle(sharedconfig.EndpointICMP, proxyHandler)
	s.mux.Handle(sharedconfig.EndpointProbe, probeHandler)

	s.httpServer = buildHTTPServer(cfg, tlsConfig, s.mux, timeout)

	routes := []string{"/", sharedconfig.EndpointTCP, sharedconfig.EndpointUDP, sharedconfig.EndpointICMP, sharedconfig.EndpointProbe}
	if s.derp != nil {
		routes = append(routes, sharedconfig.DefaultVPNDERPPath)
	}
	log.Info("[SERVER] listening", "addr", srvCfg.Listen, "routes", routes)
	s.statsDone = make(chan struct{})
	go s.statsLoop()
	return s.httpServer.ListenAndServeTLS("", "")
}

// loopbackListenAddr 由 server.listen 推导内嵌 DERP 的本机回环拨号地址
// （127.0.0.1:<listen 端口>）。
//
// 之所以能用"公网监听的回环地址"：DERP 与代理共用同一个 HTTPS 监听，而节点经
// easyss 隧道送来的 DERP 连接会在这里被改拨回环（见 handler.dialTarget）。这要求
// 该监听在回环上可达——listen 只绑了某一个非回环地址时它不可达，那属于配置错误，
// 必须在启动时明确拒绝，而不是等到节点连不上才暴露。
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
		// 地址族必须跟着监听走：只绑在 [::1] 上的监听不会接受 127.0.0.1 的连接，
		// 而 v6 通配（[::]）对 ::1 一定可用。
		if ip.Is6() {
			loopback = "::1"
		}
	}
	port, err := sharedconfig.PortFromListen(listen)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(loopback, strconv.Itoa(port)), nil
}

// startDERP 装载内嵌 DERP 中继，返回可直接挂到根处理器上的实例。addr 是它对
// 外通告的 host:port（由 ResolveDERPAddr 推导，见调用方）。
//
// 它只负责"成为一台中继"：运维只需要在本节点的 servers[] 里把对应条目标上
// "derp": true。注意它与公网入口的关系变了——DERP 处理器只会接待来自回环的
// 请求（见 vpn.NewDERPMount），节点侧经 easyss 隧道抵达。
func (s *Server) startDERP(addr string) (*vpn.DERPServer, error) {
	derpKey, err := vpn.LoadOrCreateKey(vpn.DERPKeyPath())
	if err != nil {
		log.Error("[SERVER] load derp key failed", "err", err)
		return nil, err
	}
	derpSrv := vpn.NewDERPServer(derpKey)
	log.Info("[SERVER] embedded DERP enabled",
		"derp_addr", addr,
		"path", sharedconfig.DefaultVPNDERPPath,
		"derp_public_key", derpSrv.PublicKey().String(),
		"key_file", vpn.DERPKeyPath())
	return derpSrv, nil
}

// buildHTTPServer 组装 HTTP 服务器，其 HTTP/2 流控窗口按上传吞吐量来定尺寸：
// 每流接收窗口限制了单个上传流的在途数据量（吞吐 ≈ 窗口/RTT），因此两个窗口
// 都必须足够大，以适配高 RTT 链路。
func buildHTTPServer(cfg *config.FileConfig, tlsConfig *tls.Config, mux *http.ServeMux, timeout time.Duration) *http.Server {
	http2Cfg := &http.HTTP2Config{
		MaxReadFrameSize:              sharedconfig.HTTP2ServerMaxReadFrameSize,
		MaxReceiveBufferPerConnection: sharedconfig.HTTP2ServerReceiveBufferPerConnection,
		MaxReceiveBufferPerStream:     sharedconfig.HTTP2ServerReceiveBufferPerStream,
	}
	if cfg.Transport.H2MaxFrameSize > 0 {
		http2Cfg.MaxReadFrameSize = cfg.Transport.H2MaxFrameSize
	}
	if cfg.Transport.H2RecvBufConn > 0 {
		http2Cfg.MaxReceiveBufferPerConnection = cfg.Transport.H2RecvBufConn
	}
	if cfg.Transport.H2RecvBufStream > 0 {
		http2Cfg.MaxReceiveBufferPerStream = cfg.Transport.H2RecvBufStream
	}

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
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

func (s *Server) Shutdown(ctx context.Context) error {
	log.Info("[SERVER] shutting down")

	// 停止 stats 循环 goroutine，使其不会在关闭后泄漏。
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

// stdErrorLog 将 Go 内部 http.Server/HTTP2 的日志（连接级错误、PING 超时、
// 协议错误、TLS 握手错误等）转接到 easyss 的 slog 日志器。handler 的 panic
// 由 ProxyHandler.ServeHTTP 中的 recover 单独处理。
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
