//go:build linux && !headless

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/scripts"
)

// Values used by the netns integration test below. They mirror the TUN
// defaults: the TUN gateway sits in the 198.18.0.0/15 subnet and the local
// gateway is an ordinary LAN address outside it.
const (
	testTunDevice = "tun-easyss"
	testTunIPSub  = "198.18.0.1/16"
	testTunGW     = "198.18.0.1"
	// testRoutedGateway is the local gateway of the simulated LAN. It must stay
	// outside the TUN routes (see testExcludedAddrs): the create script used to
	// install it as a host route through the TUN device, which swallowed the
	// kernel's ICMP replies to the gateway's own liveness probes.
	testRoutedGateway = "192.168.3.1"
	// testPhysDevice/testPhysAddr/testPhysGateway describe the simulated
	// physical interface: its default route keeps 0.0.0.0/8 interesting for the
	// negative probe, and testPhysLANAddr gives it a connected route on the
	// gateway's own subnet, exactly like a real LAN interface. That connected
	// route is what keeps the gateway (and the kernel's ICMP replies to it) off
	// the TUN's 128.0.0.0/1 route.
	testPhysDevice  = "phys0"
	testPhysAddr    = "192.168.9.93/24"
	testPhysGateway = "192.168.9.1"
	testPhysLANAddr = "192.168.3.93/24"
)

// testCoveredAddrs are destinations that must resolve through the TUN device
// once its routes are installed: the keep-alive probes plus one address per
// route block family. 2.2.2.2 and 3.220.72.168 cover the 2.0.0.0/7 block —
// the latter is an AWS us-east-1 address of the kind registry-1.docker.io
// resolves to, and it resolved through the physical NIC for as long as that
// block was missing from the linux and Windows ladders.
var testCoveredAddrs = []string{"1.1.1.1", "2.2.2.2", "3.220.72.168", "8.8.8.8", "223.5.5.5", "100.64.0.1"}

// testExcludedAddrs must stay outside the TUN routes. 0.0.0.0/8 is deliberately
// not routed to the TUN device, because the direct dialer probes it to find the
// physical default interface. The local gateway belongs there too: once it is
// routed into the TUN device every packet addressed to it enters the tunnel,
// and tun2socks' default ICMP forwarder only answers echo requests — the
// kernel's replies to the gateway's liveness probes would be discarded, so the
// gateway would keep probing forever (several [ICMP_DIRECT] log lines per
// second) and `ping <gateway>` would only ever see a synthetic reply. darwin
// dropped that route in 91bb4c6; linux followed.
var testExcludedAddrs = []string{"0.0.0.1", testRoutedGateway}

// TestTunRouteBlocksAreCanonical is the regression test for the broken
// "ip route add 1.0.0.0/7" line: 1.0.0.0/7 is not aligned with its own mask
// (it normalizes to 0.0.0.0/7), so iproute2 rejected it outright. Nothing
// surfaced the failure — the route was never installed, 1.0.0.0/8 silently
// leaked outside the tunnel, and the keep-alive reported "route check failed"
// every 10s.
//
// Every static prefix of every create script must therefore be canonical: a
// prefix with bits set below its mask cannot be installed by any platform's
// route command, no matter how it is spelled.
func TestTunRouteBlocksAreCanonical(t *testing.T) {
	for _, platform := range createScripts() {
		t.Run(platform.name, func(t *testing.T) {
			blocks := staticRouteBlocks(t, platform.source)
			if len(blocks) == 0 {
				t.Fatal("no static route block found: the parser and the script drifted apart")
			}
			for _, block := range blocks {
				if !block.prefix.IsValid() {
					t.Errorf("%s: unparsable route block %q", platform.name, block.raw)
					continue
				}
				if block.prefix.Masked() != block.prefix {
					t.Errorf("%s: %s is not aligned, it normalizes to %s and cannot be installed",
						platform.name, block.raw, block.prefix.Masked())
				}
			}
		})
	}
}

// TestTunRouteProbeCoveredByScripts ties the keep-alive probes to the routes
// the create scripts install: a probe outside every route block can never
// resolve through the TUN device, so the keep-alive would report a failure and
// recreate the very same routes every 10 seconds, forever.
func TestTunRouteProbeCoveredByScripts(t *testing.T) {
	for _, platform := range createScripts() {
		t.Run(platform.name, func(t *testing.T) {
			blocks := staticRouteBlocks(t, platform.source)
			for _, probe := range tunRouteProbes {
				if !routedBy(blocks, probe) {
					t.Errorf("%s: keep-alive probe %s is outside every route block %v",
						platform.name, probe, blocks)
				}
			}
		})
	}
}

// TestCreateScriptsCoverIPv4ExceptProbeBlock is the regression test for the
// missing 2.0.0.0/7 block. When the non-canonical 1.0.0.0/7 was replaced with
// 1.0.0.0/8, the linux and Windows ladders jumped straight to 4.0.0.0/6 while
// darwin's ladder starts with both blocks: 2.0.0.0/7 — 2.x and 3.x — stayed
// outside the tunnel, so every destination in it left through the physical
// NIC. registry-1.docker.io resolves to 3.x AWS addresses, which turned docker
// pulls into direct connections that the network resets instead of proxied
// ones. The platforms are checked for coverage as a whole, because every
// individual block can be spelled correctly and the script still leak.
func TestCreateScriptsCoverIPv4ExceptProbeBlock(t *testing.T) {
	for _, platform := range createScripts() {
		t.Run(platform.name, func(t *testing.T) {
			blocks := staticRouteBlocks(t, platform.source)
			if len(blocks) == 0 {
				t.Fatal("no static route block found: the parser and the script drifted apart")
			}
			requireContiguousIPv4Coverage(t, platform.name, blocks)
		})
	}
}

// TestCloseScriptsDeleteCreateRoutes asserts that every static IPv4 route a
// create script installs is deleted again by the matching close script. A
// route that outlives TUN points at a gateway on a device that no longer
// exists, which black-holes every destination in its range — worse than the
// leak it was meant to fix. The linux close script flushes the whole device
// instead (covered by TestCloseTunScriptFlushesRoutes), so it has no
// per-route list to compare against.
func TestCloseScriptsDeleteCreateRoutes(t *testing.T) {
	for _, platform := range []struct {
		name   string
		create []byte
		close  []byte
	}{
		{"darwin", scripts.CreateTunDevDarwinSh, scripts.CloseTunDevDarwinSh},
		{"windows", scripts.CreateTunDevBat, scripts.CloseTunDevBat},
	} {
		t.Run(platform.name, func(t *testing.T) {
			deletes := staticRouteDeleteBlocks(t, platform.close)
			for _, block := range staticRouteBlocks(t, platform.create) {
				if !block.prefix.IsValid() {
					continue // reported by TestTunRouteBlocksAreCanonical
				}
				want := block.prefix.Masked()
				found := slices.ContainsFunc(deletes, func(deleted routeBlock) bool {
					return deleted.prefix.IsValid() && deleted.prefix.Masked() == want
				})
				if !found {
					t.Errorf("the close script does not delete %s, it deletes: %s",
						block.raw, routeBlockRaws(deletes))
				}
			}
		})
	}
}

// TestCreateScriptsKeepGatewayOutsideTun is the regression test for routing the
// local gateway into the TUN device. The linux script used to install it as a
// bare "ip route replace $local_gateway" host route, which beat the physical
// interface's connected route for the LAN: every packet addressed to the
// gateway entered the tunnel, including the kernel's ICMP replies to the
// gateway's liveness probes. tun2socks' default ICMP forwarder answers echo
// requests only and drops every other type, so the gateway never saw a reply
// and kept probing (several [ICMP_DIRECT] log lines per second), while
// `ping <gateway>` only ever reported a synthetic sub-millisecond reply.
// darwin dropped the same route in 91bb4c6; no create script may add it back.
func TestCreateScriptsKeepGatewayOutsideTun(t *testing.T) {
	for _, platform := range createScripts() {
		t.Run(platform.name, func(t *testing.T) {
			for line := range strings.SplitSeq(string(platform.source), "\n") {
				line = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(line), "\r"))
				if line == "" || strings.HasPrefix(line, "#") ||
					strings.HasPrefix(strings.ToLower(line), "rem ") {
					continue
				}
				if !strings.Contains(line, "local_gateway") || !addsRoute(line) {
					continue
				}
				t.Errorf("%s: %s routes the local gateway into the TUN device", platform.name, line)
			}
		})
	}
}

// TestCreateTunScriptRoutesThroughTun runs the real create script in a
// throwaway network namespace and asserts what the keep-alive needs: every
// intended route is installed, the probes resolve through the TUN device, the
// 0.0.0.0/8 exclusion is preserved, and re-running the script (what the
// keep-alive does after sleep/wake) stays silent and idempotent.
//
// The device is a dummy interface because /dev/net/tun is usually unavailable
// inside an unprivileged user namespace; the ip commands the script issues are
// identical for both device types. No root privileges are needed.
func TestCreateTunScriptRoutesThroughTun(t *testing.T) {
	// The first invocation creates the device and adds the addresses, exactly
	// like the helper right after it opened the device.
	create := runCreateTunScript(tunScriptPath(t, scripts.CreateTunFilename))
	setup := tunIfaceSetup() + "\n" + physIfaceSetup()

	t.Run("routes installed", func(t *testing.T) {
		out := inNetns(t, setup+"\n"+create+"\n"+routesAndProbes())
		requireRoutesThroughTun(t, out)
	})

	t.Run("re-run is idempotent", func(t *testing.T) {
		out := inNetns(t, setup+"\n"+create+"\n"+create+"\n"+routesAndProbes())
		requireRoutesThroughTun(t, out)

		if n := strings.Count(out, "1.0.0.0/8"); n != 1 {
			t.Errorf("1.0.0.0/8 appears %d times after a re-run, want 1:\n%s", n, out)
		}
	})
}

// TestCloseTunScriptFlushesRoutes is the regression test for the TUN routes
// that survived stopping TUN and black-holed every connection. Deleting the
// interface is what removes its routes, but that delete fails with "device or
// resource busy" while a process still holds the TUN device open (the client
// closes its fd concurrently with the close script), so the close script has
// to delete the routes itself.
//
// The device is a dummy interface, which "ip tuntap del" cannot delete either
// — the very condition this test needs: the routes can only disappear through
// the flush.
func TestCloseTunScriptFlushesRoutes(t *testing.T) {
	closeTun := fmt.Sprintf("bash %s %s",
		tunScriptPath(t, scripts.CloseTunFilename), testTunDevice)

	// The device surviving the close script is what makes this test
	// meaningful: assert it stayed, otherwise the routes could just as well
	// have gone down with it.
	const keptMarker = "DEVICE_KEPT"

	body := strings.Join([]string{
		tunIfaceSetup(),
		physIfaceSetup(),
		runCreateTunScript(tunScriptPath(t, scripts.CreateTunFilename)),
		closeTun,
		"ip link show " + testTunDevice + " >/dev/null 2>&1 && echo " + keptMarker,
		routesAndProbes(),
	}, "\n")

	out := inNetns(t, body)

	if !strings.Contains(out, keptMarker) {
		t.Fatalf("the simulated device is gone, the route assertions below prove nothing:\n%s", out)
	}
	if table := routesTable(out); strings.Contains(table, "dev "+testTunDevice) {
		t.Errorf("the close script left TUN routes behind:\n%s", table)
	}
	for _, addr := range testCoveredAddrs {
		if got := probeOutput(out, addr); strings.Contains(got, "dev "+testTunDevice) {
			t.Errorf("ip route get %s = %q, want it to leave the TUN device", addr, got)
		}
	}
}

// tunScriptPath returns the absolute path of an embedded script, so a test
// runs the same file the helper executes.
func tunScriptPath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return path
}

// tunIfaceSetup creates the dummy interface that stands in for the TUN device.
func tunIfaceSetup() string {
	return `ip link add "` + testTunDevice + `" type dummy && ip link set dev lo up`
}

// physIfaceSetup creates the simulated physical interface. It carries the LAN
// address as well as a subnet of its own: the LAN connected route is what a
// real interface has, and the extra subnet's default route keeps 0.0.0.0/8
// interesting for the negative probe (0.0.0.1 must resolve, just not through
// the TUN device).
func physIfaceSetup() string {
	return fmt.Sprintf(`ip link add %s type dummy && ip addr add %s dev %s`+
		` && ip addr add %s dev %s && ip link set %s up && ip route add default via %s dev %s`,
		testPhysDevice, testPhysAddr, testPhysDevice, testPhysLANAddr, testPhysDevice,
		testPhysDevice, testPhysGateway, testPhysDevice)
}

// routesAndProbes dumps the resulting routing table and one marked "ip route
// get" result per probe address. The kernel answers the lookups, so a route
// block that is spelled in a way which does not route (as 1.0.0.0/7 was)
// cannot pass by matching text, and the probes are emitted only once the table
// is final.
func routesAndProbes() string {
	var b strings.Builder
	b.WriteString("ip route show | grep -v '^default'\n")
	for _, addr := range append(slices.Clone(testCoveredAddrs), testExcludedAddrs...) {
		fmt.Fprintf(&b, "echo '%s %s' \"$(ip route get %s 2>&1 | head -1)\"\n",
			probeMarker, addr, addr)
	}
	return b.String()
}

// probeMarker prefixes every probe result line in the captured output.
const probeMarker = "PROBE"

// requireRoutesThroughTun asserts the routing state the TUN helper relies on.
func requireRoutesThroughTun(t *testing.T, out string) {
	t.Helper()

	table := routesTable(out)
	for _, cidr := range []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	} {
		// Compare masked prefixes: the kernel prints a host route as its bare
		// address ("192.168.3.1"), which parses to 192.168.3.1/32, while the
		// expected value above is spelled with the same host in the network.
		want := netip.MustParsePrefix(cidr).Masked()
		found := slices.ContainsFunc(strings.Split(table, "\n"), func(line string) bool {
			prefix, ok := routedPrefix(line)
			return ok && prefix.Masked() == want
		})
		if !found {
			t.Errorf("route %s via %s dev %s is missing:\n%s", cidr, testTunGW, testTunDevice, table)
		}
	}

	for _, addr := range testCoveredAddrs {
		if got := probeOutput(out, addr); !strings.Contains(got, "dev "+testTunDevice) {
			t.Errorf("ip route get %s = %q, want it to resolve through %s", addr, got, testTunDevice)
		}
	}

	for _, addr := range testExcludedAddrs {
		if got := probeOutput(out, addr); strings.Contains(got, "dev "+testTunDevice) {
			t.Errorf("ip route get %s = %q, want it to stay outside the TUN routes", addr, got)
		}
	}

	// The gateway keeps resolving (through the physical interface's default
	// route), so its own liveness probes reach this host and its ICMP replies
	// leave through the physical interface.
	if got := probeOutput(out, testRoutedGateway); !strings.Contains(got, "dev "+testPhysDevice) {
		t.Errorf("ip route get %s = %q, want it to resolve through %s",
			testRoutedGateway, got, testPhysDevice)
	}
}

// probeOutput returns the captured lookup result for addr.
func probeOutput(out, addr string) string {
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(line, probeMarker+" "+addr+" ")
		if ok {
			return rest
		}
	}
	return ""
}

// routesTable returns the "ip route show" portion of the captured output, i.e.
// every line that starts with a route prefix.
func routesTable(out string) string {
	var table []string
	for line := range strings.SplitSeq(out, "\n") {
		if _, ok := routedPrefix(line); ok {
			table = append(table, line)
		}
	}
	return strings.Join(table, "\n")
}

// inNetns runs body with bash inside a throwaway unprivileged network
// namespace and returns its combined output. It skips when the environment
// does not support unprivileged user namespaces (rootless containers without
// CLONE_NEWUSER), so the suite stays green there.
func inNetns(t *testing.T, body string) string {
	t.Helper()

	cmd := exec.Command("unshare", "-Urn", "bash", "-c", body)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		res := string(out)
		if strings.Contains(res, "Operation not permitted") ||
			strings.Contains(res, "unshare:") ||
			strings.Contains(res, "executable file not found") {
			t.Skipf("unshare is unavailable in this environment: %v\n%s", err, res)
		}
		t.Fatalf("netns body failed: %v\n%s", err, res)
	}
	if res := string(out); strings.Contains(res, "[create_tun_dev]") {
		t.Errorf("the create script reported a non-idempotent error:\n%s", res)
	}
	return string(out)
}

// runCreateTunScript returns the shell snippet that executes the create script
// with the same arguments the client passes on Linux.
func runCreateTunScript(scriptPath string) string {
	return fmt.Sprintf("bash %s %s %s %s %s",
		scriptPath, testTunDevice, testTunIPSub, testTunGW, testRoutedGateway)
}

// createScripts returns the create scripts of every platform, parseable from
// any host because they are embedded.
func createScripts() []struct {
	name   string
	source []byte
} {
	return []struct {
		name   string
		source []byte
	}{
		{"linux", scripts.CreateTunDevSh},
		{"darwin", scripts.CreateTunDevDarwinSh},
		{"windows", scripts.CreateTunDevBat},
	}
}

// routedPrefix extracts the destination prefix from a line of "ip route show"
// output ("4.0.0.0/6 via 198.18.0.1 dev tun-easyss"). A bare address is a host
// route.
func routedPrefix(line string) (netip.Prefix, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(fields[0]); err == nil {
		return prefix, true
	}
	if addr, err := netip.ParseAddr(fields[0]); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// routeBlock is one IPv4 route a create script installs. prefix is invalid
// when the script spells a non-canonical prefix (for example 1.0.0.0/7, which
// normalizes to 0.0.0.0/7), so callers can report it verbatim.
type routeBlock struct {
	raw    string
	prefix netip.Prefix
}

// routedBy reports whether addr is a destination covered by any of the blocks,
// i.e. whether a lookup in that routing state resolves through the TUN device.
func routedBy(blocks []routeBlock, addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, block := range blocks {
		if block.prefix.IsValid() && block.prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// requireContiguousIPv4Coverage asserts the route blocks cover every address
// above 0.0.0.0/8, i.e. one contiguous ladder from 1.0.0.0 up to
// 255.255.255.255, and that 0.0.0.0/8 itself stays outside the tunnel.
func requireContiguousIPv4Coverage(t *testing.T, name string, blocks []routeBlock) {
	t.Helper()

	// 0.0.0.0/8 stays outside deliberately: the direct dialer probes 0.0.0.1 to
	// find the physical default interface, and a covered probe would resolve to
	// the TUN device, which the dialer must never bind to (a routing loop).
	for _, addr := range []string{"0.0.0.1", "0.255.255.255"} {
		if routedBy(blocks, addr) {
			t.Errorf("%s: %s is covered by a route block, want 0.0.0.0/8 to stay outside the TUN routes",
				name, addr)
		}
	}

	// Walk the space above 0.0.0.0/8 block by block: the first address no block
	// covers starts a gap, and every destination inside it leaks outside the
	// tunnel (see the 2.0.0.0/7 hole).
	for cur := uint32(1) << 24; ; {
		last, ok := lastCoveringBlock(blocks, cur)
		if !ok {
			t.Errorf("%s: no route block covers %s, the range leaks outside the TUN device",
				name, addrFromUint32(cur))
			return
		}
		if last == ^uint32(0) {
			return
		}
		cur = last + 1
	}
}

// lastCoveringBlock returns the highest end address among the blocks that
// contain addr, and whether any block contains it at all. Blocks that are not
// canonical prefixes are ignored: TestTunRouteBlocksAreCanonical reports them.
func lastCoveringBlock(blocks []routeBlock, addr uint32) (uint32, bool) {
	var (
		last    uint32
		covered bool
	)
	for _, block := range blocks {
		if !block.prefix.IsValid() || !block.prefix.Addr().Is4() {
			continue
		}
		base := addrToUint32(block.prefix.Masked().Addr())
		end := base | (^uint32(0) >> uint(block.prefix.Bits()))
		if base <= addr && addr <= end && (!covered || end > last) {
			last, covered = end, true
		}
	}
	return last, covered
}

// addrToUint32 converts an IPv4 address to its big-endian integer form.
func addrToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

// addrFromUint32 is the inverse of addrToUint32.
func addrFromUint32(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

// routeBlockRaws returns the raw spellings of blocks, the form a failure
// message can show without netip's internals.
func routeBlockRaws(blocks []routeBlock) string {
	raws := make([]string, 0, len(blocks))
	for _, block := range blocks {
		raws = append(raws, block.raw)
	}
	return strings.Join(raws, ", ")
}

// createRouteVerbs are the route verbs a create script installs routes with:
// the linux script uses "ip route replace" (idempotent re-runs after
// sleep/wake), darwin and windows "route add".
var createRouteVerbs = []string{"add", "replace"}

// staticRouteBlocks parses the IPv4 route destinations a create script
// installs, in every dialect the scripts are written in: "ip route
// add|replace <prefix>" (linux), "route add -net <prefix>" (darwin) and
// "route add <addr> mask <mask>" (windows). Routes built from shell variables
// (the local gateway) and IPv6 lines are skipped.
func staticRouteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, createRouteVerbs)
}

// staticRouteDeleteBlocks parses the IPv4 destinations a close script removes
// ("route delete ...", "ip route delete|del ..."). The linux close script
// flushes every route of the TUN device instead, so it contributes no blocks.
func staticRouteDeleteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, []string{"delete", "del"})
}

// parseRouteBlocks parses the static IPv4 route destinations of a script for
// the given route verbs.
func parseRouteBlocks(t *testing.T, script []byte, verbs []string) []routeBlock {
	t.Helper()

	var blocks []routeBlock
	for line := range strings.SplitSeq(string(script), "\n") {
		line = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(line), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "rem ") {
			continue
		}

		fields := strings.Fields(line)
		// The linux script wraps its ip calls in the run_idem shell helper.
		if idx := slices.IndexFunc(fields, func(f string) bool { return f == "ip" || f == "route" }); idx > 0 {
			fields = fields[idx:]
		}
		switch fields[0] {
		case "ip":
			// linux: ip route replace 1.0.0.0/8 via "$tun_gw" dev "$tun_device"
			args, ok := routeArgs(fields[1:], verbs)
			if !ok {
				continue
			}
			appendStaticBlock(t, &blocks, args[0])
		case "route":
			// windows: route add 1.0.0.0 mask 254.0.0.0 %tun_gw% metric 5
			// darwin:  route add -net 1.0.0.0/8 "$tun_gw"
			args, ok := routeArgs(fields[1:], verbs)
			if !ok {
				continue
			}
			switch {
			case args[0] == "-net" && len(args) >= 2: // darwin
				appendStaticBlock(t, &blocks, args[1])
			case len(args) >= 3 && args[1] == "mask": // windows
				appendStaticBlock(t, &blocks, args[0]+" "+args[2])
			default:
				t.Fatalf("unrecognized route line: %q", line)
			}
		}
	}
	return blocks
}

// addsRoute reports whether line is a route command that adds or replaces a
// route, in any of the dialects the create scripts are written in
// ("ip route add|replace ...", "route add ...").
func addsRoute(line string) bool {
	fields := strings.Fields(line)
	// The linux script wraps its ip calls in the run_idem shell helper.
	if idx := slices.IndexFunc(fields, func(f string) bool { return f == "ip" || f == "route" }); idx > 0 {
		fields = fields[idx:]
	}
	return slices.ContainsFunc(fields, func(f string) bool { return slices.Contains(createRouteVerbs, f) })
}

// routeArgs returns the fields following one of the given route verbs,
// reporting false for lines that neither add/delete a route nor refer to a
// static destination.
func routeArgs(fields []string, verbs []string) ([]string, bool) {
	idx := slices.IndexFunc(fields, func(f string) bool { return slices.Contains(verbs, f) })
	if idx < 0 || idx+1 >= len(fields) {
		return nil, false
	}
	args := fields[idx+1:]
	// Dynamic destinations (the local gateway) and IPv6 lines are not part of
	// the static IPv4 route set this test checks.
	if strings.Contains(args[0], "$") || strings.Contains(args[0], "%") ||
		slices.Contains(fields, "-inet6") || strings.Contains(args[0], ":") {
		return nil, false
	}
	return args, true
}

// appendStaticBlock records a static route destination, ignoring dynamic
// (shell/batch variable) destinations.
func appendStaticBlock(t *testing.T, blocks *[]routeBlock, raw string) {
	t.Helper()

	if strings.Contains(raw, "$") || strings.Contains(raw, "%") {
		return
	}
	block := newRouteBlock(t, raw)
	if block.prefix.IsValid() && !block.prefix.Addr().Is4() {
		return // IPv6 blocks are not covered by the IPv4 probes
	}
	*blocks = append(*blocks, block)
}

// newRouteBlock builds a routeBlock from an "address/prefixlen" pair or from
// an "address mask" pair. An unrecognized or malformed input yields an invalid
// prefix, so callers report it instead of silently dropping the route.
func newRouteBlock(t *testing.T, raw string) routeBlock {
	t.Helper()

	parts := strings.Fields(raw)
	switch len(parts) {
	case 1:
		prefix, err := netip.ParsePrefix(parts[0])
		if err != nil {
			return routeBlock{raw: raw}
		}
		return routeBlock{raw: raw, prefix: prefix}
	case 2:
		addr, err := netip.ParseAddr(parts[0])
		if err != nil {
			t.Fatalf("route block %q: %v", raw, err)
		}
		mask := net.ParseIP(parts[1]).To4()
		if mask == nil {
			return routeBlock{raw: raw}
		}
		ones, bits := net.IPMask(mask).Size()
		if bits != 32 {
			return routeBlock{raw: raw}
		}
		// PrefixFrom keeps the destination as spelled instead of masking it down
		// (Addr.Prefix would turn "1.0.0.0 mask 254.0.0.0" into 0.0.0.0/7 and hide
		// the mistake), so a destination that is not the network address of its
		// own mask is reported by TestTunRouteBlocksAreCanonical.
		return routeBlock{raw: raw, prefix: netip.PrefixFrom(addr, ones)}
	default:
		t.Fatalf("unrecognized route block %q", raw)
		return routeBlock{raw: raw}
	}
}
