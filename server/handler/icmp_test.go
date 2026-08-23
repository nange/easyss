package handler

import (
	"testing"

	"github.com/nange/easyss/v3/util"
)

func TestLanHostOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8"},              // bare IP (IPConn.RemoteAddr)
		{"8.8.8.8:9", "8.8.8.8"},            // TCP/UDP form
		{"2001:db8::1", "2001:db8::1"},      // bare IPv6
		{"[2001:db8::1]:53", "2001:db8::1"}, // IPv6 with port
		{"fe80::1%en0", "fe80::1"},          // bare IPv6 with zone
		{"[fe80::1%en0]:0", "fe80::1%en0"},  // IPv6 with port and zone
		{"", ""},
	}
	for _, tt := range tests {
		if got := lanHostOf(tt.in); got != tt.want {
			t.Errorf("lanHostOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestLanHostOfSSRFGuard pins the post-dial SSRF check: the host extracted
// from an IPConn-style bare address must feed util.IsLANIP unchanged, or a
// DNS-rebinding name resolving to a LAN host would slip past the guard.
func TestLanHostOfSSRFGuard(t *testing.T) {
	for _, lan := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "fe80::1"} {
		if !util.IsLANIP(lanHostOf(lan)) {
			t.Errorf("lan host %q must be rejected by the SSRF guard", lan)
		}
	}
	for _, pub := range []string{"8.8.8.8", "1.1.1.1:53", "2001:4860:4860::8888"} {
		if util.IsLANIP(lanHostOf(pub)) {
			t.Errorf("public host %q must pass the SSRF guard", pub)
		}
	}
}
