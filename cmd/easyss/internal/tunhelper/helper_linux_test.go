//go:build linux && !headless

package tunhelper

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
	"github.com/stretchr/testify/require"
)

// 取值与 TUN 默认值一致：TUN 网关在 198.18.0.0/15 子网内，本地网关是其外的普通局域网地址。
const (
	testTunDevice = "tun-easyss"
	testTunIPSub  = "198.18.0.1/16"
	testTunGW     = "198.18.0.1"
	// 必须留在 TUN 路由之外：把它装成经由 TUN 设备的主机路由会吞掉内核发给网关的 ICMP 回复。
	testRoutedGateway = "192.168.3.1"
	// 物理接口自带默认路由与 LAN 直连路由，后者把网关挡在 TUN 的 128.0.0.0/1 路由之外。
	testPhysDevice  = "phys0"
	testPhysAddr    = "192.168.9.93/24"
	testPhysGateway = "192.168.9.1"
	testPhysLANAddr = "192.168.3.93/24"
)

// 路由安装后必须经由 TUN 设备解析的目标，2.2.2.2 与 3.220.72.168 覆盖 2.0.0.0/7 块。
var testCoveredAddrs = []string{"1.1.1.1", "2.2.2.2", "3.220.72.168", "8.8.8.8", "223.5.5.5", "100.64.0.1"}

// 必须留在 TUN 路由之外：0.0.0.0/8 被直连拨号器用于探测物理默认接口，
// 网关一旦进隧道，tun2socks 只应答回显请求，内核发出的回复会被丢弃。
var testExcludedAddrs = []string{"0.0.0.1", testRoutedGateway}

// 前缀必须与自己掩码对齐：1.0.0.0/7 会被规范化为 0.0.0.0/7 并被 iproute2 直接拒绝，
// 路由从未安装而 1.0.0.0/8 静默泄漏出隧道，失败没有任何表象。
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

// 探测地址必须被某个路由块覆盖：落在所有块之外就永远无法经由 TUN 解析，
// keep-alive 会每 10 秒重建同样的路由。
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

// 缺失 2.0.0.0/7 块时 2.x 与 3.x 留在隧道之外，registry-1.docker.io 解析到的
// AWS 地址会绕过代理。覆盖范围按平台整体检查，单个块写对了脚本仍可能泄漏。
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

// create 脚本装的每条静态 IPv4 路由都要被 close 脚本删掉：比 TUN 活得久的路由指向
// 已不存在的设备，会黑洞其范围内所有目标。linux 改为清空整个设备的路由，没有逐路由列表。
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
					continue // 由 TestTunRouteBlocksAreCanonical 报告
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

// 网关不得路由进 TUN 设备：裸的 ip route replace 会压过物理接口的 LAN 直连路由，
// 发往网关的包全部进隧道，tun2socks 只应答回显请求，网关存活探测永远收不到回复。
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

// 在一次性 netns 里跑真实的 create 脚本，断言路由、探测地址解析、0.0.0.0/8 排除规则，
// 并验证重跑幂等。dummy 接口代替 TUN：无特权用户命名空间通常没有 /dev/net/tun，
// 脚本发出的 ip 命令对两种设备相同。
func TestCreateTunScriptRoutesThroughTun(t *testing.T) {
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

// 接口删不掉时路由才会残留：有进程仍持有 TUN 设备时 ip tuntap del 会报
// "device or resource busy"，因此 close 脚本必须自己删路由。dummy 接口同样删不掉，
// 路由只能通过清空操作消失。
func TestCloseTunScriptFlushesRoutes(t *testing.T) {
	closeTun := fmt.Sprintf("bash %s %s",
		tunScriptPath(t, scripts.CloseTunFilename), testTunDevice)

	// 设备在 close 脚本之后仍在，是断言有意义的前提。
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

func tunScriptPath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", name))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return path
}

func tunIfaceSetup() string {
	return `ip link add "` + testTunDevice + `" type dummy && ip link set dev lo up`
}

// 模拟的物理接口同时承载 LAN 地址与自己的子网：LAN 直连路由挡住网关，
// 默认路由让 0.0.0.0/8 对反向探测保持有效。
func physIfaceSetup() string {
	return fmt.Sprintf(`ip link add %s type dummy && ip addr add %s dev %s`+
		` && ip addr add %s dev %s && ip link set %s up && ip route add default via %s dev %s`,
		testPhysDevice, testPhysAddr, testPhysDevice, testPhysLANAddr, testPhysDevice,
		testPhysDevice, testPhysGateway, testPhysDevice)
}

// 查找由内核回答，写错的前缀无法蒙混；探测只在路由表定型之后输出。
func routesAndProbes() string {
	var b strings.Builder
	b.WriteString("ip route show | grep -v '^default'\n")
	for _, addr := range append(slices.Clone(testCoveredAddrs), testExcludedAddrs...) {
		fmt.Fprintf(&b, "echo '%s %s' \"$(ip route get %s 2>&1 | head -1)\"\n",
			probeMarker, addr, addr)
	}
	return b.String()
}

const probeMarker = "PROBE"

func requireRoutesThroughTun(t *testing.T, out string) {
	t.Helper()

	table := routesTable(out)
	for _, cidr := range []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	} {
		// 内核把主机路由打印成裸地址（"192.168.3.1" 即 /32），比较前要掩码化。
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

	// 网关经由物理接口可解析，它自己的存活探测与内核的回复都不进隧道。
	if got := probeOutput(out, testRoutedGateway); !strings.Contains(got, "dev "+testPhysDevice) {
		t.Errorf("ip route get %s = %q, want it to resolve through %s",
			testRoutedGateway, got, testPhysDevice)
	}
}

func probeOutput(out, addr string) string {
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(line, probeMarker+" "+addr+" ")
		if ok {
			return rest
		}
	}
	return ""
}

func routesTable(out string) string {
	var table []string
	for line := range strings.SplitSeq(out, "\n") {
		if _, ok := routedPrefix(line); ok {
			table = append(table, line)
		}
	}
	return strings.Join(table, "\n")
}

// 无特权用户命名空间不可用时（没有 CLONE_NEWUSER 的无根容器）跳过测试。
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

func runCreateTunScript(scriptPath string) string {
	return fmt.Sprintf("bash %s %s %s %s %s",
		scriptPath, testTunDevice, testTunIPSub, testTunGW, testRoutedGateway)
}

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

type routeBlock struct {
	raw    string
	prefix netip.Prefix
}

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

func requireContiguousIPv4Coverage(t *testing.T, name string, blocks []routeBlock) {
	t.Helper()

	// 0.0.0.0/8 留在外面：直连拨号器探测 0.0.0.1 找物理默认接口，
	// 被覆盖就会解析到 TUN 设备，拨号器绑定上去即形成路由环路。
	for _, addr := range []string{"0.0.0.1", "0.255.255.255"} {
		if routedBy(blocks, addr) {
			t.Errorf("%s: %s is covered by a route block, want 0.0.0.0/8 to stay outside the TUN routes",
				name, addr)
		}
	}

	// 第一个没有被块覆盖的地址就是一个缺口，其内每个目标都会泄漏出隧道。
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

// 非规范前缀的块被忽略，由 TestTunRouteBlocksAreCanonical 报告。
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

func addrToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

func addrFromUint32(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

func routeBlockRaws(blocks []routeBlock) string {
	raws := make([]string, 0, len(blocks))
	for _, block := range blocks {
		raws = append(raws, block.raw)
	}
	return strings.Join(raws, ", ")
}

var createRouteVerbs = []string{"add", "replace"}

// 覆盖脚本用到的各种方言：ip route add|replace（linux）、route add -net（darwin）、
// route add <addr> mask <mask>（windows）；shell 变量构建的动态目标与 IPv6 行跳过。
func staticRouteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, createRouteVerbs)
}

// linux 的 close 脚本清空整个设备的路由，因此不贡献任何块。
func staticRouteDeleteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, []string{"delete", "del"})
}

// 去掉 unix 脚本放在每个工具调用前的 run_idem/fail/del 前缀，否则方言检测会把
// linux 路由阶梯里的步骤名 "route" 当作命令。
func unwrapScriptHelper(fields []string) []string {
	if len(fields) < 3 {
		return fields
	}
	switch fields[0] {
	case "run_idem", "fail", "del":
		return fields[2:]
	}
	return fields
}

func parseRouteBlocks(t *testing.T, script []byte, verbs []string) []routeBlock {
	t.Helper()

	var blocks []routeBlock
	for line := range strings.SplitSeq(string(script), "\n") {
		line = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(line), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "rem ") {
			continue
		}

		fields := unwrapScriptHelper(strings.Fields(line))
		if idx := slices.IndexFunc(fields, func(f string) bool { return f == "ip" || f == "route" }); idx > 0 {
			fields = fields[idx:]
		}
		switch fields[0] {
		case "ip":
			args, ok := routeArgs(fields[1:], verbs)
			if !ok {
				continue
			}
			appendStaticBlock(t, &blocks, args[0])
		case "route":
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

func addsRoute(line string) bool {
	fields := unwrapScriptHelper(strings.Fields(line))
	if idx := slices.IndexFunc(fields, func(f string) bool { return f == "ip" || f == "route" }); idx > 0 {
		fields = fields[idx:]
	}
	return slices.ContainsFunc(fields, func(f string) bool { return slices.Contains(createRouteVerbs, f) })
}

func routeArgs(fields []string, verbs []string) ([]string, bool) {
	idx := slices.IndexFunc(fields, func(f string) bool { return slices.Contains(verbs, f) })
	if idx < 0 || idx+1 >= len(fields) {
		return nil, false
	}
	args := fields[idx+1:]
	if strings.Contains(args[0], "$") || strings.Contains(args[0], "%") ||
		slices.Contains(fields, "-inet6") || strings.Contains(args[0], ":") {
		return nil, false
	}
	return args, true
}

func appendStaticBlock(t *testing.T, blocks *[]routeBlock, raw string) {
	t.Helper()

	if strings.Contains(raw, "$") || strings.Contains(raw, "%") {
		return
	}
	block := newRouteBlock(t, raw)
	if block.prefix.IsValid() && !block.prefix.Addr().Is4() {
		return // IPv6 块不在 IPv4 探测的覆盖范围内
	}
	*blocks = append(*blocks, block)
}

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
		// Addr.Prefix 会把 "1.0.0.0 mask 254.0.0.0" 归一化成 0.0.0.0/7 而掩盖错误，
		// 因此用 PrefixFrom 保留原样，让非规范目标被 TestTunRouteBlocksAreCanonical 报出来。
		return routeBlock{raw: raw, prefix: netip.PrefixFrom(addr, ones)}
	default:
		t.Fatalf("unrecognized route block %q", raw)
		return routeBlock{raw: raw}
	}
}

// 判据是整词匹配的设备名：子串匹配会让 "tun" 命中 "tun0"，误判成残留并触发提权回滚。
func TestTunRouteResidueUsesTheTunDevice(t *testing.T) {
	const (
		viaTun      = "1.1.1.1 dev tun-easyss src 198.18.0.1 uid 501"
		viaPhysical = "1.1.1.1 via 192.168.3.1 dev en0 src 192.168.3.20 uid 501"
	)

	t.Run("still routed via the tun device", func(t *testing.T) {
		run, calls := stubRouteProbe(viaTun)

		out, leftover := probeTunRouteResidue(run, "tun-easyss", "")
		require.True(t, leftover, "traffic still entering the session's device means the teardown failed")
		require.Contains(t, out, "dev tun-easyss")
		require.Equal(t, []string{"ip", "route", "get", "1.1.1.1"}, (*calls)[0],
			"the linux probe is `ip route get <probe>`")
	})

	t.Run("routed via the physical device", func(t *testing.T) {
		run, _ := stubRouteProbe(viaPhysical)

		_, leftover := probeTunRouteResidue(run, "tun-easyss", "")
		require.False(t, leftover, "the physical device means the teardown worked")
	})

	t.Run("a device name that is only a prefix does not match", func(t *testing.T) {
		run, _ := stubRouteProbe("1.1.1.1 dev tun0 src 198.18.0.1 uid 501")

		_, leftover := probeTunRouteResidue(run, "tun", "")
		require.False(t, leftover)
	})

	t.Run("without a device name there is nothing to judge", func(t *testing.T) {
		run, calls := stubRouteProbe(viaTun)

		_, leftover := probeTunRouteResidue(run, "", "")
		require.False(t, leftover)
		require.Empty(t, *calls, "no probe may run without a device to look for")
	})
}
