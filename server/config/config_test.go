package config

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nange/easyss/v3/util"
)

// TestFileConfigJSON pins the documented config shape: the top-level settings
// live on FileConfig and the "server" key maps onto ServerConfig, with no
// duplicated fields between them.
func TestFileConfigJSON(t *testing.T) {
	data := []byte(`{
			"version": 3,
		"server": {
			"listen": ":443",
			"domain": "example.com",
			"password": "secret",
			"allowed_methods": ["aes-256-gcm"],
			"timeout": 99,
			"next_proxy": {"url": "socks5://127.0.0.1:9999", "enable_udp": false}
		},
		"fallback": {"target": "fallback.html"},
		"next_proxy": {"url": "socks5://127.0.0.1:1080", "enable_udp": true},
		"pprof_enabled": true,
		"timeout": 30
	}`)

	var fc FileConfig
	require.NoError(t, json.Unmarshal(data, &fc))
	require.Equal(t, ":443", fc.Server.Listen)
	require.Equal(t, "secret", fc.Server.Password)
	require.Equal(t, []string{"aes-256-gcm"}, fc.Server.AllowedMethods)
	require.Equal(t, "fallback.html", fc.Fallback.Target)
	require.Equal(t, 30, fc.Timeout)
	require.Equal(t, "socks5://127.0.0.1:1080", fc.NextProxy.URL)
	require.True(t, fc.NextProxy.EnableUDP)
	require.True(t, fc.PprofEnabled)
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

// TestResolveFilePathsCarriesIntoResolvedPaths pins that ResolveFilePaths
// rewrites the fields in place: there is no second copy of them to keep in
// sync after the EffectiveServerConfig merge was removed.
func TestResolveFilePathsResolvedInPlace(t *testing.T) {
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

	if want := filepath.Join(util.CurrentDir(), "server.crt"); fc.Server.CertPath != want {
		t.Errorf("CertPath = %q, want %q", fc.Server.CertPath, want)
	}
	if want := filepath.Join(util.CurrentDir(), "next_proxy.txt"); fc.NextProxy.NextProxyFile != want {
		t.Errorf("NextProxyFile = %q, want %q", fc.NextProxy.NextProxyFile, want)
	}
	if fc.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", fc.Timeout)
	}
}
