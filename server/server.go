package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/server/nextproxy"
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
	tlsConfig, err := s.initTLS()
	if err != nil {
		return err
	}

	timeout := time.Duration(s.cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if s.cfg.FallbackHTMLPath != "" {
		fallbackHTML, err := os.ReadFile(s.cfg.FallbackHTMLPath)
		if err != nil {
			return fmt.Errorf("load fallback html: %w", err)
		}
		handler.SetFallbackHTML(fallbackHTML)
	}

	masterKey, err := crypto.DeriveMasterKey(s.cfg.Password)
	if err != nil {
		return fmt.Errorf("derive master key: %w", err)
	}

	np, err := nextproxy.New(s.cfg.NextProxy.URL, s.cfg.NextProxy.EnableUDP, s.cfg.NextProxy.AllHost)
	if err != nil {
		return fmt.Errorf("next proxy: %w", err)
	}
	if np != nil {
		if err := np.LoadIPDomainFiles(s.cfg.NextProxy.IPsFile, s.cfg.NextProxy.DomainsFile); err != nil {
			return fmt.Errorf("next proxy load ip/domain: %w", err)
		}
	}

	proxyHandler := handler.NewProxyHandler(handler.ProxyHandlerConfig{
		MasterKey:         masterKey,
		AllowedMethods:    s.cfg.GetAllowedMethods(),
		HandshakeTimeout:  timeout / 2,
		StreamIdleTimeout: timeout / 2,
		UDPIdleTimeout:    timeout,
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
		Protocols: &http.Protocols{},
		HTTP2: &http.HTTP2Config{
			SendPingTimeout:  timeout / 2,
			WriteByteTimeout: timeout / 2,
		},
		IdleTimeout:       timeout / 2,
		ReadHeaderTimeout: min(timeout/2, 10*time.Second),
	}
	s.httpServer.Protocols.SetHTTP1(true)
	s.httpServer.Protocols.SetHTTP2(true)

	return s.httpServer.ListenAndServeTLS("", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.certCache != nil {
		s.certCache.Stop()
		s.certCache = nil
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
