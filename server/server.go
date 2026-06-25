package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/stats"
)

type Server struct {
	cfg        *config.ServerConfig
	httpServer *http.Server
	mux        *http.ServeMux
	certCache  *certmagic.Cache
}

func New(cfg *config.ServerConfig) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) initTLS() (*tls.Config, error) {
	cfg := s.cfg

	if cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
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
		_ = cleanCertmagicDomainAssets(context.Background(), storage, cfg.Domain)
		tlsConfig, cache, err = s.manageCert(storage, true)
	}
	if err != nil {
		if cache != nil {
			cache.Stop()
		}
		return nil, fmt.Errorf("certmagic: %w", err)
	}

	s.certCache = cache
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
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
	acmeCfg.Email = s.cfg.Email
	acmeCfg.DisableHTTPChallenge = true
	cmCfg.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(cmCfg, acmeCfg)}

	tlsConfig := cmCfg.TLSConfig()
	err := cmCfg.ManageSync(context.Background(), []string{s.cfg.Domain})
	if err != nil {
		return nil, cache, err
	}
	return tlsConfig, cache, nil
}

func (s *Server) resolveEmail(storagePath string) {
	if s.cfg.Email != "" {
		return
	}
	if existing := findExistingACMEEmail(storagePath); existing != "" {
		s.cfg.Email = existing
		log.Info("[SERVER] reused existing ACME email", "email", existing)
		return
	}
	s.cfg.Email = randomEmail()
	log.Info("[SERVER] generated random ACME email", "email", s.cfg.Email)
}

func (s *Server) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		snap := stats.Collect()
		log.Info("[SERVER_STATS]",
			"uptime", snap.Uptime().Round(time.Second),
			"tx", stats.HumanBytes(snap.BytesSent),
			"rx", stats.HumanBytes(snap.BytesRecv),
			"tcp", snap.ServerTCPStreams,
			"udp", snap.ServerUDPStreams,
			"icmp", snap.ServerICMPStreams,
			"hserr", snap.ServerHandshakeErrors,
			"fallback", snap.ServerFallbackPages,
			"padding", stats.HumanBytes(snap.PaddingBytes),
			"records", snap.RecordsWritten,
		)
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
	return "admin-" + hex.EncodeToString(b) + "@example.com"
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
	log.Info("[SERVER] starting", "listen", cfg.Listen, "domain", cfg.Domain, "timeout", cfg.Timeout)

	tlsConfig, err := s.initTLS()
	if err != nil {
		log.Error("[SERVER] init TLS failed", "err", err)
		return err
	}
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		log.Info("[SERVER] TLS mode: cert files", "cert", cfg.CertPath, "key", cfg.KeyPath)
	} else {
		log.Info("[SERVER] TLS mode: certmagic (Let's Encrypt)", "domain", cfg.Domain, "email", cfg.Email)
	}

	timeout := time.Duration(s.cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if s.cfg.FallbackTarget != "" {
		if err := handler.SetFallbackTarget(s.cfg.FallbackTarget); err != nil {
			return fmt.Errorf("fallback target: %w", err)
		}
		log.Info("[SERVER] fallback target configured", "target", s.cfg.FallbackTarget)
	}

	masterKey, err := crypto.DeriveMasterKey(s.cfg.Password)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	np, err := nextproxy.New(s.cfg.NextProxy.URL, s.cfg.NextProxy.EnableUDP, s.cfg.NextProxy.AllHost)
	if err != nil {
		log.Error("[SERVER] next proxy init failed", "err", err)
		return fmt.Errorf("next proxy: %w", err)
	}
	if np != nil {
		if err := np.LoadProxyFile(s.cfg.NextProxy.NextProxyFile); err != nil {
			log.Error("[SERVER] next proxy load file failed", "err", err)
			return fmt.Errorf("next proxy load file: %w", err)
		}
		log.Info("[SERVER] next proxy configured", "url", s.cfg.NextProxy.URL, "udp", s.cfg.NextProxy.EnableUDP, "all_host", s.cfg.NextProxy.AllHost)
	}

	streamIdleTimeout := time.Duration(sharedconfig.DefaultTCPStreamIdleTimeout) * time.Second
	if 4*timeout > streamIdleTimeout {
		streamIdleTimeout = 4 * timeout
	}

	proxyHandler := handler.NewProxyHandler(handler.ProxyHandlerConfig{
		MasterKey:         masterKey,
		AllowedMethods:    s.cfg.GetAllowedMethods(),
		HandshakeTimeout:  timeout / 2,
		StreamIdleTimeout: streamIdleTimeout,
		UDPIdleTimeout:    timeout,
		BatchWindowMS:     s.cfg.BatchWindowMS,
		NextProxy:         np,
	})

	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeFallback(w, r)
	})
	s.mux.Handle("/v3/tcp", proxyHandler)
	s.mux.Handle("/v3/udp", proxyHandler)
	s.mux.Handle("/v3/icmp", proxyHandler)

	s.httpServer = &http.Server{
		Addr:      s.cfg.Listen,
		TLSConfig: tlsConfig,
		Handler:   s.mux,
		ErrorLog:  stdErrorLog(),
		Protocols: &http.Protocols{},
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              sharedconfig.DefaultHTTP2MaxReadFrameSize,
			MaxReceiveBufferPerConnection: sharedconfig.DefaultHTTP2ReceiveBufferPerConnection,
			MaxReceiveBufferPerStream:     sharedconfig.DefaultHTTP2ReceiveBufferPerStream,
			SendPingTimeout:               timeout / 2,
		},
		IdleTimeout:       timeout / 2,
		ReadHeaderTimeout: min(timeout/2, 10*time.Second),
	}
	s.httpServer.Protocols.SetHTTP1(true)
	s.httpServer.Protocols.SetHTTP2(true)

	log.Info("[SERVER] listening", "addr", s.cfg.Listen, "routes", []string{"/", "/v3/tcp", "/v3/udp", "/v3/icmp"})
	go s.statsLoop()
	return s.httpServer.ListenAndServeTLS("", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Info("[SERVER] shutting down")

	if s.certCache != nil {
		s.certCache.Stop()
		s.certCache = nil
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// stdErrorLog routes Go's internal http.Server/HTTP2 logs (connection-level
// errors, PING timeouts, protocol errors, TLS handshake errors, etc.) through
// easyss's slog logger. Handler panics are handled separately by the recover
// in ProxyHandler.ServeHTTP.
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
