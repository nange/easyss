//go:build linux

package util

import (
	"reflect"
	"strings"
	"testing"
)

// recordingTunDNS 替换 tunDNSCommand，以便在不触碰运行测试的机器
// 的解析器的情况下断言 DNS 配置。
type recordingTunDNS struct {
	commands [][]string
	replies  map[string]string
}

func (r *recordingTunDNS) run(name string, args ...string) (string, error) {
	cmd := append([]string{name}, args...)
	r.commands = append(r.commands, cmd)
	return r.replies[strings.Join(cmd, " ")], nil
}

func (r *recordingTunDNS) install(t *testing.T) {
	t.Helper()

	restore := tunDNSCommand
	tunDNSCommand = r.run
	t.Cleanup(func() { tunDNSCommand = restore })
}

func TestSetTunLinkDNSPinsResolverToTun(t *testing.T) {
	iface, err := defaultInterface()
	if err != nil {
		t.Skipf("no default interface in this environment: %v", err)
	}

	rec := &recordingTunDNS{}
	rec.install(t)

	if err := setTunLinkDNS("tun-easyss", []string{"223.5.5.5"}); err != nil {
		t.Fatalf("setTunLinkDNS: %v", err)
	}

	want := [][]string{
		{"resolvectl", "dns", "tun-easyss", "223.5.5.5"},
		{"resolvectl", "domain", "tun-easyss", "~."},
		{"resolvectl", "default-route", "tun-easyss", "yes"},
		{"resolvectl", "default-route", iface, "no"},
	}
	if !reflect.DeepEqual(rec.commands, want) {
		t.Errorf("commands = %v, want %v", rec.commands, want)
	}
}

func TestEnsureSysDNSForTunReassertsState(t *testing.T) {
	iface, err := defaultInterface()
	if err != nil {
		t.Skipf("no default interface in this environment: %v", err)
	}

	cases := []struct {
		name string
		// reply 是 "resolvectl default-route <link>" 查询返回的内容。
		reply string
		// wantCmds 统计该查询加上所有需要重新应用的命令数。
		wantCmds int
	}{
		// 物理链路仍不在 DNS 默认路由上：TUN 状态完好，只发出了查询。
		{"state in place", "Link 2 (" + iface + "): no", 1},
		// NetworkManager 把 DNS 默认路由交还给了物理链路：解析将再次
		// 绕过隧道，因此需要重新应用状态（查询 + 四条命令）。
		{"physical link took it back", "Link 2 (" + iface + "): yes", 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingTunDNS{replies: map[string]string{
				"resolvectl default-route " + iface: tc.reply,
			}}
			rec.install(t)

			if err := EnsureSysDNSForTun("tun-easyss", []string{"223.5.5.5"}); err != nil {
				t.Fatalf("EnsureSysDNSForTun: %v", err)
			}
			if len(rec.commands) != tc.wantCmds {
				t.Errorf("issued %d commands (%v), want %d", len(rec.commands), rec.commands, tc.wantCmds)
			}
		})
	}
}

func TestResolvectlBool(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Link 2 (wlp0s20f3): no", "no"},
		{"Link 2 (wlp0s20f3): yes", "yes"},
		// 链路名称绝不能与答案混淆。
		{"Link 2 (eno1): no", "no"},
		{"Link 2 (eno1): yes", "yes"},
		{"eno1", ""},
		{"", ""},
	}

	for _, tc := range cases {
		if got := resolvectlBool(tc.in); got != tc.want {
			t.Errorf("resolvectlBool(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
