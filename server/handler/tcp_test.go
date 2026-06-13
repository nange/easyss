package handler

import (
	"net"
	"testing"
)

func TestOutboundTCPNetwork(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "domain",
			addr: "ipv6.msftncsi.com:80",
			want: "tcp",
		},
		{
			name: "ipv4 literal",
			addr: "192.0.2.1:80",
			want: "tcp4",
		},
		{
			name: "ipv6 literal",
			addr: net.JoinHostPort("2001:db8::1", "80"),
			want: "tcp6",
		},
		{
			name: "invalid hostport",
			addr: "missing-port",
			want: "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outboundTCPNetwork(tt.addr); got != tt.want {
				t.Fatalf("outboundTCPNetwork(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
