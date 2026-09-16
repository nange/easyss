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

// 以下 netns 集成测试使用的取值。它们与 TUN 默认值一致：TUN 网关位于
// 198.18.0.0/15 子网内，而本地网关是位于其外的普通局域网地址。
const (
	testTunDevice = "tun-easyss"
	testTunIPSub  = "198.18.0.1/16"
	testTunGW     = "198.18.0.1"
	// testRoutedGateway 是模拟局域网的本地网关。它必须留在 TUN 路由之外
	// （参见 testExcludedAddrs）：create 脚本曾把它作为经由 TUN 设备的主机路由
	// 安装，结果吞掉了内核针对网关自身存活探测发出的 ICMP 回复。
	testRoutedGateway = "192.168.3.1"
	// testPhysDevice/testPhysAddr/testPhysGateway 描述模拟的物理接口：它的默认
	// 路由让 0.0.0.0/8 对反向探测保持有效，而 testPhysLANAddr 为它提供网关所在
	// 子网上的直连路由，与真实局域网接口完全一致。正是这条直连路由把网关（以及
	// 内核发给它的 ICMP 回复）挡在 TUN 的 128.0.0.0/1 路由之外。
	testPhysDevice  = "phys0"
	testPhysAddr    = "192.168.9.93/24"
	testPhysGateway = "192.168.9.1"
	testPhysLANAddr = "192.168.3.93/24"
)

// testCoveredAddrs 是在 TUN 路由安装后必须经由 TUN 设备解析的目标：包含
// keep-alive 探测地址以及每个路由块族的一个地址。2.2.2.2 和 3.220.72.168
// 覆盖 2.0.0.0/7 块——后者是 registry-1.docker.io 所解析的那类 AWS us-east-1
// 地址，在 linux 和 Windows 路由阶梯缺失该块的期间，它一直经由物理网卡解析。
var testCoveredAddrs = []string{"1.1.1.1", "2.2.2.2", "3.220.72.168", "8.8.8.8", "223.5.5.5", "100.64.0.1"}

// testExcludedAddrs 必须留在 TUN 路由之外。0.0.0.0/8 刻意不路由进 TUN 设备，
// 因为直接拨号器探测它来寻找物理默认接口。本地网关同样属于此列：一旦它被路由进
// TUN 设备，发往它的每个数据包都会进入隧道，而 tun2socks 默认的 ICMP 转发器
// 只应答回显请求——内核针对网关存活探测发出的回复会被丢弃，于是网关会永远探测
// 下去（每秒数条 [ICMP_DIRECT] 日志），`ping <gateway>` 也只能看到合成的回复。
// darwin 在 91bb4c6 中删掉了那条路由；linux 紧随其后。
var testExcludedAddrs = []string{"0.0.0.1", testRoutedGateway}

// TestTunRouteBlocksAreCanonical 是那条有问题的 "ip route add 1.0.0.0/7" 行的
// 回归测试：1.0.0.0/7 与它自身的掩码不对齐（会被规范化为 0.0.0.0/7），因此
// iproute2 直接拒绝了它。失败没有任何表象——路由从未安装，1.0.0.0/8 静默地
// 泄漏到隧道之外，keep-alive 每 10 秒报告一次 "route check failed"。
//
// 因此，每个 create 脚本的每个静态前缀都必须是规范形式：掩码以下仍有置位的前缀
// 无法被任何平台的 route 命令安装，无论它怎么写。
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

// TestTunRouteProbeCoveredByScripts 把 keep-alive 探测地址与 create 脚本安装的
// 路由绑定在一起：落在所有路由块之外的探测地址永远无法经由 TUN 设备解析，于是
// keep-alive 会不断报告失败并每 10 秒重新创建同样的路由，永无止境。
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

// TestCreateScriptsCoverIPv4ExceptProbeBlock 是缺失 2.0.0.0/7 块的回归测试。
// 当非规范的 1.0.0.0/7 被替换为 1.0.0.0/8 后，linux 和 Windows 的路由阶梯直接
// 跳到 4.0.0.0/6，而 darwin 的阶梯以两个块开头：2.0.0.0/7——即 2.x 和 3.x——
// 留在了隧道之外，其中的每个目标都经由物理网卡离开。registry-1.docker.io
// 解析到 3.x 的 AWS 地址，导致 docker 拉取变成被网络重置的直连，而不是走代理。
// 各平台作为一个整体检查覆盖范围，因为即使每个单独的块都写对了，脚本仍可能泄漏。
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

// TestCloseScriptsDeleteCreateRoutes 断言 create 脚本安装的每一条静态 IPv4 路由
// 都会被对应的 close 脚本再次删除。一条比 TUN 存活得更久的路由指向一个已不存在的
// 设备上的网关，会黑洞其范围内的所有目标——比它本想修复的泄漏更糟。linux 的
// close 脚本改为清空整个设备的路由（由 TestCloseTunScriptFlushesRoutes 覆盖），
// 因此没有逐路由列表可比对。
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

// TestCreateScriptsKeepGatewayOutsideTun 是把本地网关路由进 TUN 设备的回归测试。
// linux 脚本曾把它作为一条裸的 "ip route replace $local_gateway" 主机路由安装，
// 压过了物理接口对局域网的直连路由：发往网关的每个数据包都进入隧道，包括内核
// 针对网关存活探测发出的 ICMP 回复。tun2socks 默认的 ICMP 转发器只应答回显请求，
// 丢弃其他所有类型，于是网关永远看不到回复而持续探测（每秒数条 [ICMP_DIRECT]
// 日志），`ping <gateway>` 也只报告合成的亚毫秒级回复。darwin 在 91bb4c6 中
// 删掉了同一条路由；任何 create 脚本都不得再把它加回去。
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

// TestCreateTunScriptRoutesThroughTun 在一次性网络命名空间中运行真实的 create
// 脚本，并断言 keep-alive 所需的一切：所有预期的路由都已安装、探测地址经由 TUN
// 设备解析、0.0.0.0/8 排除规则仍然保留，而且重新运行脚本（即 keep-alive 在
// 睡眠/唤醒后所做的）保持静默且幂等。
//
// 设备使用 dummy 接口，因为无特权的用户命名空间内通常没有 /dev/net/tun；脚本发出
// 的 ip 命令对两种设备类型完全相同。无需 root 权限。
func TestCreateTunScriptRoutesThroughTun(t *testing.T) {
	// 第一次调用会创建设备并添加地址，与辅助进程打开设备后所做的完全一致。
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

// TestCloseTunScriptFlushesRoutes 是针对停止 TUN 后残留并黑洞所有连接的 TUN 路由
// 的回归测试。删除接口本会带走其路由，但只要有进程仍持有 TUN 设备打开，删除就会
// 以 "device or resource busy" 失败（客户端与 close 脚本并发地关闭其 fd），因此
// close 脚本必须自行删除这些路由。
//
// 设备使用 dummy 接口，"ip tuntap del" 同样无法删除它——这正是本测试需要的条件：
// 路由只能通过清空操作消失。
func TestCloseTunScriptFlushesRoutes(t *testing.T) {
	closeTun := fmt.Sprintf("bash %s %s",
		tunScriptPath(t, scripts.CloseTunFilename), testTunDevice)

	// 设备在 close 脚本之后仍然存在，正是本测试有意义的前提：断言它还在，
	// 否则路由本可以随它一起消失。
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

// tunScriptPath 返回内嵌脚本的绝对路径，使测试运行与辅助进程相同的文件。
func tunScriptPath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return path
}

// tunIfaceSetup 创建代替 TUN 设备的 dummy 接口。
func tunIfaceSetup() string {
	return `ip link add "` + testTunDevice + `" type dummy && ip link set dev lo up`
}

// physIfaceSetup 创建模拟的物理接口。它同时承载 LAN 地址和其自有的子网：
// LAN 直连路由是真实接口所具备的，而接口的默认路由让 0.0.0.0/8 对反向探测保持
// 有效（0.0.0.1 必须能解析，只是不能经由 TUN 设备）。
func physIfaceSetup() string {
	return fmt.Sprintf(`ip link add %s type dummy && ip addr add %s dev %s`+
		` && ip addr add %s dev %s && ip link set %s up && ip route add default via %s dev %s`,
		testPhysDevice, testPhysAddr, testPhysDevice, testPhysLANAddr, testPhysDevice,
		testPhysDevice, testPhysGateway, testPhysDevice)
}

// routesAndProbes 导出最终的路由表，以及每个探测地址对应的一条带标记的
// "ip route get" 结果。查找由内核回答，因此以某种无法路由的方式书写（如过去的
// 1.0.0.0/7）的路由块不可能靠文本匹配蒙混过关；探测只在路由表定型之后才输出。
func routesAndProbes() string {
	var b strings.Builder
	b.WriteString("ip route show | grep -v '^default'\n")
	for _, addr := range append(slices.Clone(testCoveredAddrs), testExcludedAddrs...) {
		fmt.Fprintf(&b, "echo '%s %s' \"$(ip route get %s 2>&1 | head -1)\"\n",
			probeMarker, addr, addr)
	}
	return b.String()
}

// probeMarker 为捕获输出中的每条探测结果行添加前缀。
const probeMarker = "PROBE"

// requireRoutesThroughTun 断言 TUN 辅助进程所依赖的路由状态。
func requireRoutesThroughTun(t *testing.T, out string) {
	t.Helper()

	table := routesTable(out)
	for _, cidr := range []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	} {
		// 比较掩码化后的前缀：内核把主机路由打印为裸地址（"192.168.3.1"），
		// 它会被解析为 192.168.3.1/32，而上文期望值则用网络中的同一主机书写。
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

	// 网关始终可解析（经由物理接口的默认路由），因此它自身的存活探测能到达
	// 本机，而内核的 ICMP 回复也经由物理接口离开。
	if got := probeOutput(out, testRoutedGateway); !strings.Contains(got, "dev "+testPhysDevice) {
		t.Errorf("ip route get %s = %q, want it to resolve through %s",
			testRoutedGateway, got, testPhysDevice)
	}
}

// probeOutput 返回捕获输出中 addr 的查找结果。
func probeOutput(out, addr string) string {
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(line, probeMarker+" "+addr+" ")
		if ok {
			return rest
		}
	}
	return ""
}

// routesTable 返回捕获输出中的 "ip route show" 部分，即以路由前缀开头的每一行。
func routesTable(out string) string {
	var table []string
	for line := range strings.SplitSeq(out, "\n") {
		if _, ok := routedPrefix(line); ok {
			table = append(table, line)
		}
	}
	return strings.Join(table, "\n")
}

// inNetns 在一次性无特权网络命名空间中用 bash 运行 body，并返回其合并输出。
// 当环境不支持无特权用户命名空间（没有 CLONE_NEWUSER 的无根容器）时跳过测试，
// 使测试套件在该环境中保持通过。
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

// runCreateTunScript 返回执行 create 脚本的 shell 片段，参数与客户端在 Linux 上
// 传入的相同。
func runCreateTunScript(scriptPath string) string {
	return fmt.Sprintf("bash %s %s %s %s %s",
		scriptPath, testTunDevice, testTunIPSub, testTunGW, testRoutedGateway)
}

// createScripts 返回各平台的 create 脚本；由于它们是内嵌的，在任何主机上都能解析。
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

// routedPrefix 从一行 "ip route show" 输出（"4.0.0.0/6 via 198.18.0.1 dev tun-easyss"）
// 中提取目标前缀。裸地址即主机路由。
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

// routeBlock 是 create 脚本安装的一条 IPv4 路由。当脚本书写了非规范前缀时
// （例如 1.0.0.0/7，它会被规范化为 0.0.0.0/7），prefix 无效，调用方可以
// 原样报告它。
type routeBlock struct {
	raw    string
	prefix netip.Prefix
}

// routedBy 报告 addr 是否是被任一路由块覆盖的目标，即在该路由状态下查找是否会
// 经由 TUN 设备解析。
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

// requireContiguousIPv4Coverage 断言路由块覆盖 0.0.0.0/8 之上的每个地址，
// 即从 1.0.0.0 到 255.255.255.255 的一段连续阶梯，且 0.0.0.0/8 本身
// 留在隧道之外。
func requireContiguousIPv4Coverage(t *testing.T, name string, blocks []routeBlock) {
	t.Helper()

	// 0.0.0.0/8 刻意留在外面：直接拨号器探测 0.0.0.1 以寻找物理默认接口，
	// 若该探测地址被覆盖就会解析到 TUN 设备，而拨号器绝不能绑定到它（会形成
	// 路由环路）。
	for _, addr := range []string{"0.0.0.1", "0.255.255.255"} {
		if routedBy(blocks, addr) {
			t.Errorf("%s: %s is covered by a route block, want 0.0.0.0/8 to stay outside the TUN routes",
				name, addr)
		}
	}

	// 逐块遍历 0.0.0.0/8 之上的地址空间：第一个没有块覆盖的地址就是一个缺口，
	// 其内的每个目标都会泄漏到隧道之外（参见 2.0.0.0/7 的漏洞）。
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

// lastCoveringBlock 返回包含 addr 的块中最高的结束地址，以及是否有块包含它。
// 非规范前缀的块会被忽略：TestTunRouteBlocksAreCanonical 会报告它们。
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

// addrToUint32 将 IPv4 地址转换为其大端整数形式。
func addrToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.BigEndian.Uint32(a[:])
}

// addrFromUint32 是 addrToUint32 的逆运算。
func addrFromUint32(v uint32) netip.Addr {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

// routeBlockRaws 返回路由块的原始拼写，即失败消息无需暴露 netip 内部细节即可
// 展示的形式。
func routeBlockRaws(blocks []routeBlock) string {
	raws := make([]string, 0, len(blocks))
	for _, block := range blocks {
		raws = append(raws, block.raw)
	}
	return strings.Join(raws, ", ")
}

// createRouteVerbs 是 create 脚本安装路由所用的动词：linux 脚本使用
// "ip route replace"（睡眠/唤醒后幂等地重跑），darwin 和 windows 使用
// "route add"。
var createRouteVerbs = []string{"add", "replace"}

// staticRouteBlocks 解析 create 脚本安装的 IPv4 路由目标，覆盖脚本所用的各种
// 方言："ip route add|replace <prefix>"（linux）、"route add -net <prefix>"
// （darwin）和 "route add <addr> mask <mask>"（windows）。由 shell 变量构建的
// 路由（本地网关）以及 IPv6 行会被跳过。
func staticRouteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, createRouteVerbs)
}

// staticRouteDeleteBlocks 解析 close 脚本移除的 IPv4 目标
// （"route delete ..."、"ip route delete|del ..."）。linux 的 close 脚本改为
// 清空 TUN 设备的全部路由，因此它不贡献任何块。
func staticRouteDeleteBlocks(t *testing.T, script []byte) []routeBlock {
	t.Helper()

	return parseRouteBlocks(t, script, []string{"delete", "del"})
}

// unwrapScriptHelper 去掉 unix create 脚本放在每个工具调用前的 shell 辅助函数：
// "run_idem STEP cmd ..."（linux）和 "fail STEP cmd ..."（darwin）。步骤名是
// 普通单词，linux 用于路由阶梯的步骤名恰好就是 "route"：若保留它，下面的方言
// 检测会把步骤名当作命令，从而错误解析该行。
func unwrapScriptHelper(fields []string) []string {
	if len(fields) >= 3 && (fields[0] == "run_idem" || fields[0] == "fail") {
		return fields[2:]
	}
	return fields
}

// parseRouteBlocks 按给定的路由动词解析脚本中的静态 IPv4 路由目标。
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
			// linux：ip route replace 1.0.0.0/8 via "$tun_gw" dev "$tun_device"
			args, ok := routeArgs(fields[1:], verbs)
			if !ok {
				continue
			}
			appendStaticBlock(t, &blocks, args[0])
		case "route":
			// windows：route add 1.0.0.0 mask 254.0.0.0 %tun_gw% metric 5
			// darwin： route add -net 1.0.0.0/8 "$tun_gw"
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

// addsRoute 报告 line 是否是添加或替换路由的路由命令，覆盖 create 脚本所用的
// 各种方言（"ip route add|replace ..."、"route add ..."）。
func addsRoute(line string) bool {
	fields := unwrapScriptHelper(strings.Fields(line))
	if idx := slices.IndexFunc(fields, func(f string) bool { return f == "ip" || f == "route" }); idx > 0 {
		fields = fields[idx:]
	}
	return slices.ContainsFunc(fields, func(f string) bool { return slices.Contains(createRouteVerbs, f) })
}

// routeArgs 返回给定路由动词之后的字段；对既不添加/删除路由、也不涉及静态目标的
// 行返回 false。
func routeArgs(fields []string, verbs []string) ([]string, bool) {
	idx := slices.IndexFunc(fields, func(f string) bool { return slices.Contains(verbs, f) })
	if idx < 0 || idx+1 >= len(fields) {
		return nil, false
	}
	args := fields[idx+1:]
	// 动态目标（本地网关）和 IPv6 行不属于本测试检查的静态 IPv4 路由集合。
	if strings.Contains(args[0], "$") || strings.Contains(args[0], "%") ||
		slices.Contains(fields, "-inet6") || strings.Contains(args[0], ":") {
		return nil, false
	}
	return args, true
}

// appendStaticBlock 记录静态路由目标，忽略动态（shell/batch 变量）目标。
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

// newRouteBlock 从 "address/prefixlen" 对或 "address mask" 对构建 routeBlock。
// 无法识别或格式错误的输入会得到无效前缀，调用方因此会报告它而不是静默丢弃
// 该路由。
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
		// PrefixFrom 会按原样保留目标地址而不是按掩码归一化（Addr.Prefix 会把
		// "1.0.0.0 mask 254.0.0.0" 变成 0.0.0.0/7 从而掩盖错误），因此一个不是
		// 自身掩码网络地址的目标会被 TestTunRouteBlocksAreCanonical 报告出来。
		return routeBlock{raw: raw, prefix: netip.PrefixFrom(addr, ones)}
	default:
		t.Fatalf("unrecognized route block %q", raw)
		return routeBlock{raw: raw}
	}
}
