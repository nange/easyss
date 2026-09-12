//go:build linux

package util

import (
	"reflect"
	"strings"
	"testing"
)

// recordingTunDNS replaces tunDNSCommand so the DNS setup can be asserted
// without touching the resolver of the machine running the test.
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
		// reply is what the "resolvectl default-route <link>" lookup returns.
		reply string
		// wantCmds counts that lookup plus whatever had to be re-applied.
		wantCmds int
	}{
		// The physical link is still out of the DNS default route: the TUN
		// state survived and only the lookup was issued.
		{"state in place", "Link 2 (" + iface + "): no", 1},
		// NetworkManager handed the DNS default route back to the physical
		// link: resolution would bypass the tunnel again, so the state is
		// re-applied (lookup + four commands).
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
		// A link name must never be mistaken for the answer.
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
