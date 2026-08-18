package config

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nange/easyss/v3/util"
)

func TestFileConfigEffectiveServerConfig(t *testing.T) {
	data := []byte(`{
			"version": 3,
		"server": {
			"listen": ":443",
			"domain": "example.com",
			"password": "secret",
			"allowed_methods": ["aes-256-gcm"],
				"fallback_target": "fallback.html",
			"timeout": 99,
			"next_proxy": {"url": "socks5://127.0.0.1:9999", "enable_udp": false}
		},
		"next_proxy": {"url": "socks5://127.0.0.1:1080", "enable_udp": true},
		"timeout": 30
	}`)

	var fc FileConfig
	require.NoError(t, json.Unmarshal(data, &fc))
	cfg := fc.EffectiveServerConfig()
	require.Equal(t, ":443", cfg.Listen)
	require.Equal(t, "secret", cfg.Password)
	require.Equal(t, "fallback.html", cfg.FallbackTarget)
	require.Equal(t, 30, cfg.Timeout)
	require.Equal(t, "socks5://127.0.0.1:1080", cfg.NextProxy.URL)
	require.True(t, cfg.NextProxy.EnableUDP)
}

func TestResolveFilePaths(t *testing.T) {
	relCert := "server.crt"
	relNextProxy := "next_proxy.txt"
	abs, err := filepath.Abs("server.key")
	if err != nil {
		t.Fatal(err)
	}

	fc := &FileConfig{
		Server: ServerConfig{
			CertPath: relCert,
			KeyPath:  abs,
		},
		NextProxy: NextProxyConfig{
			NextProxyFile: relNextProxy,
		},
	}

	fc.ResolveFilePaths()

	if want := filepath.Join(util.CurrentDir(), relCert); fc.Server.CertPath != want {
		t.Errorf("CertPath = %q, want %q", fc.Server.CertPath, want)
	}
	if fc.Server.KeyPath != abs {
		t.Errorf("KeyPath = %q, want %q (absolute unchanged)", fc.Server.KeyPath, abs)
	}
	if want := filepath.Join(util.CurrentDir(), relNextProxy); fc.NextProxy.NextProxyFile != want {
		t.Errorf("NextProxyFile = %q, want %q", fc.NextProxy.NextProxyFile, want)
	}
}

func TestResolveFilePathsEmpty(t *testing.T) {
	fc := &FileConfig{}
	fc.ResolveFilePaths()

	if fc.Server.CertPath != "" || fc.Server.KeyPath != "" || fc.NextProxy.NextProxyFile != "" {
		t.Errorf("empty paths should stay empty, got %+v", fc)
	}
}

func TestEffectiveServerConfigCarriesResolvedPaths(t *testing.T) {
	fc := &FileConfig{
		Server: ServerConfig{
			CertPath: "server.crt",
			KeyPath:  "server.key",
		},
		NextProxy: NextProxyConfig{
			NextProxyFile: "next_proxy.txt",
		},
		Timeout: 30,
	}

	fc.ResolveFilePaths()
	cfg := fc.EffectiveServerConfig()

	if cfg.CertPath != fc.Server.CertPath {
		t.Errorf("effective CertPath = %q, want %q", cfg.CertPath, fc.Server.CertPath)
	}
	if cfg.NextProxy.NextProxyFile != fc.NextProxy.NextProxyFile {
		t.Errorf("effective NextProxyFile = %q, want %q", cfg.NextProxy.NextProxyFile, fc.NextProxy.NextProxyFile)
	}
	if cfg.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", cfg.Timeout)
	}
}
