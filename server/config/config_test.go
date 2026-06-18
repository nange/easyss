package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileConfigEffectiveServerConfig(t *testing.T) {
	data := []byte(`{
			"version": 3,
		"server": {
			"listen": ":443",
			"domain": "example.com",
			"password": "secret",
			"allowed_methods": ["aes-256-gcm"],
			"fallback_html_path": "fallback.html"
		},
		"next_proxy": {"url": "socks5://127.0.0.1:1080", "enable_udp": true},
		"timeout": 30
	}`)

	var fc FileConfig
	require.NoError(t, json.Unmarshal(data, &fc))
	cfg := fc.EffectiveServerConfig()
	require.Equal(t, ":443", cfg.Listen)
	require.Equal(t, "secret", cfg.Password)
	require.Equal(t, "fallback.html", cfg.FallbackHTMLPath)
	require.Equal(t, 30, cfg.Timeout)
	require.Equal(t, "socks5://127.0.0.1:1080", cfg.NextProxy.URL)
	require.True(t, cfg.NextProxy.EnableUDP)
}
