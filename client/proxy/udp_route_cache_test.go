package proxy

import (
	"testing"

	"github.com/nange/easyss/v3/client/router"
)

func TestUDPRouteCacheInvalidatedByRuleGeneration(t *testing.T) {
	t.Parallel()

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	cache := newUDPRouteCache()
	const host = "udp-route-cache.invalid"

	if got := cache.classify(rt, host).Rule; got != router.HostRuleProxy {
		t.Fatalf("initial classification = %v, want proxy", got)
	}

	// 动态学习新增直连域名后，缓存必须随规则版本失效，不能继续返回旧分类。
	rt.AddDirectDomain(host)
	if got := cache.classify(rt, host).Rule; got != router.HostRuleDirect {
		t.Fatalf("classification after AddDirectDomain = %v, want direct", got)
	}

	// 全局代理模式变化同样要 bump 版本。
	rt.SetProxyRule(router.ProxyRuleDirect)
	if got := cache.classify(rt, "another.invalid").Rule; got != router.HostRuleDirect {
		t.Fatalf("classification after SetProxyRule = %v, want direct", got)
	}
}
