package proxy

import (
	"slices"
	"testing"
)

// TestDedupeDNSUpstreams 验证候选上游去重且保持首次出现的顺序。TUN 的系统 DNS
// 现在取自内置池（见 easydns.PreferredSystemDNS），直连分支会把它作为 reqServer
// 前置到同一个池上，因此重复候选是常态：不去重就会对同一台服务器重复拨号。
func TestDedupeDNSUpstreams(t *testing.T) {
	in := []string{"223.5.5.5:53", "119.29.29.29:53", "223.5.5.5:53", "114.114.114.114:53", "119.29.29.29:53"}
	want := []string{"223.5.5.5:53", "119.29.29.29:53", "114.114.114.114:53"}

	if got := dedupeDNSUpstreams(in); !slices.Equal(got, want) {
		t.Errorf("dedupeDNSUpstreams = %v, want %v", got, want)
	}

	if got := dedupeDNSUpstreams(nil); len(got) != 0 {
		t.Errorf("dedupeDNSUpstreams(nil) = %v, want empty", got)
	}
}
