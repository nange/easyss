//go:build (darwin || linux) && !headless

package app

import (
	"context"
	"errors"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
)

// 共享进程级的 DNS 熔断/可达记录/系统 DNS 缓存，因此必须串行（不能 t.Parallel）。
func TestPreResolveHelperServerResetsStaleResolverState(t *testing.T) {
	easydns.ResetResolveState()
	t.Cleanup(easydns.ResetResolveState)

	// 上一次网络留下的可达记录：不作废就会被 PreferredSystemDNS 按首次成功顺序优先选中。
	easydns.MarkSystemServerReachable("192.168.1.1:53")

	var seen string
	core := fakePreResolver{fn: func(context.Context, string, []string, bool) error {
		seen = easydns.PreferredSystemDNS()
		return errors.New("all dns servers failed")
	}}

	cfg := &clientconfig.ClientConfig{
		Servers: []*clientconfig.ServerProfile{{Host: "example.com", Port: 443}},
	}
	if err := preResolveHelperServer(core, cfg); err == nil {
		t.Fatal("pre-resolve failure must abort TUN enable")
	}
	if seen != clientconfig.DefaultSystemDNS {
		t.Fatalf("stale resolver still visible during pre-resolve: PreferredSystemDNS = %q, want %q",
			seen, clientconfig.DefaultSystemDNS)
	}
}

type fakePreResolver struct {
	fn func(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error
}

func (f fakePreResolver) PrePopulateServerDomain(
	ctx context.Context, domain string, dnsServers []string, requireIPv4 bool,
) error {
	return f.fn(ctx, domain, dnsServers, requireIPv4)
}
