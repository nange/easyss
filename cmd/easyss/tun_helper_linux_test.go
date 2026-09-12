//go:build linux && !headless

package main

import (
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
	// testRoutedGateway is the local gateway the script routes through the TUN
	// device: a LAN router whose own subnet is not connected in the test, so
	// the only route that can match it is the TUN one.
	testRoutedGateway = "192.168.3.1"
	// testPhysAddr/testPhysGateway describe the simulated physical interface
	// (its default route keeps 0.0.0.0/8 interesting for the negative probe).
	testPhysAddr    = "192.168.9.93/24"
	testPhysGateway = "192.168.9.1"
)

// testCoveredAddrs are destinations that must resolve through the TUN device
// once its routes are installed: the keep-alive probes plus one address per
// route block family.
var testCoveredAddrs = []string{"1.1.1.1", "8.8.8.8", "223.5.5.5", "100.64.0.1"}

// testExcludedAddr must stay outside the TUN routes: 0.0.0.0/8 is deliberately
// not routed to the TUN device, because the direct dialer probes it to find
// the physical default interface.
const testExcludedAddr = "0.0.0.1"

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
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "scripts", scripts.CreateTunFilename))
	if err != nil {
		t.Fatalf("resolve script path: %v", err)
	}

	// The first invocation creates the device and adds the addresses, exactly
	// like the helper right after it opened the device.
	create := runCreateTunScript(scriptPath)
	tunSetup := `ip link add "` + testTunDevice + `" type dummy && ip link set dev lo up`
	// The simulated physical interface sits on a subnet of its own so that the
	// local gateway the script routes has no competing connected route; its
	// default route is what makes the negative probe meaningful (0.0.0.1 must
	// resolve, just not through the TUN device).
	physSetup := fmt.Sprintf(`ip link add phys0 type dummy && ip addr add %s dev phys0`+
		` && ip link set phys0 up && ip route add default via %s dev phys0`,
		testPhysAddr, testPhysGateway)
	setup := tunSetup + "\n" + physSetup

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

// routesAndProbes dumps the resulting routing table and one marked "ip route
// get" result per probe address. The kernel answers the lookups, so a route
// block that is spelled in a way which does not route (as 1.0.0.0/7 was)
// cannot pass by matching text, and the probes are emitted only once the table
// is final.
func routesAndProbes() string {
	var b strings.Builder
	b.WriteString("ip route show | grep -v '^default'\n")
	for _, addr := range append(slices.Clone(testCoveredAddrs), testExcludedAddr) {
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
		"1.0.0.0/8", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1", testRoutedGateway + "/32",
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

	if got := probeOutput(out, testExcludedAddr); strings.Contains(got, "dev "+testTunDevice) {
		t.Errorf("ip route get %s = %q, want it to stay outside the TUN routes", testExcludedAddr, got)
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

// staticRouteBlocks parses the IPv4 route destinations a create script
// installs, in every dialect the scripts are written in: "ip route
// add|replace <prefix>" (linux), "route add -net <prefix>" (darwin) and
// "route add <addr> mask <mask>" (windows). Routes built from shell variables
// (the local gateway) and IPv6 lines are skipped.
func staticRouteBlocks(t *testing.T, script []byte) []routeBlock {
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
			args, ok := routeArgs(fields[1:])
			if !ok {
				continue
			}
			appendStaticBlock(t, &blocks, args[0])
		case "route":
			// windows: route add 1.0.0.0 mask 254.0.0.0 %tun_gw% metric 5
			// darwin:  route add -net 1.0.0.0/8 "$tun_gw"
			args, ok := routeArgs(fields[1:])
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

// routeArgs returns the fields following the add/replace verb of a route
// command, reporting false for lines that neither add a route nor refer to a
// static destination.
func routeArgs(fields []string) ([]string, bool) {
	idx := slices.IndexFunc(fields, func(f string) bool { return f == "add" || f == "replace" })
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
		prefix, err := addr.Prefix(ones)
		if err != nil {
			return routeBlock{raw: raw}
		}
		return routeBlock{raw: raw, prefix: prefix}
	default:
		t.Fatalf("unrecognized route block %q", raw)
		return routeBlock{raw: raw}
	}
}
