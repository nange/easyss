package nextproxy

import (
	"os/exec"
	"strings"
	"testing"
)

// allowedTun2socksPackages 是服务端依赖闭包里允许出现的 tun2socks 包。用 go list
// 的真实 import 闭包断言，才抓得到不经意的间接引用：服务端只为 transport/socks5
// 引用 tun2socks，引到 WireGuard 引擎或 gVisor netstack 会让二进制大十几 MiB。
// 刻意用精确路径而非 "transport/" 前缀，后者会把 transport/shadowsocks 一并放行。
var allowedTun2socksPackages = map[string]struct{}{
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5":              {},
	"github.com/xjasonlyu/tun2socks/v2/transport/internal/bufferpool": {},
	"github.com/xjasonlyu/tun2socks/v2/internal/pool":                 {},
}

// serverPackage 是被检查的入口：服务端二进制的 main 包。
const serverPackage = "../../cmd/easyss-server"

// forbiddenServerDeps 是不允许被服务端间接引入的重量级依赖。它们是客户端
// TUN 模式的实现（WireGuard 引擎 + 用户态网络栈），与服务端的职责无关。
var forbiddenServerDeps = []string{
	"github.com/xjasonlyu/tun2socks/v2/engine",
	"github.com/xjasonlyu/tun2socks/v2/core",
	"github.com/xjasonlyu/wireguard-go",
	"gvisor.dev/gvisor",
	"github.com/tailscale/tailcat",
}

// TestServerDepsKeepTun2socksProtocolOnly 断言服务端的依赖闭包里 tun2socks 只有协议层
// 这几个包，且没有任何重量级引擎/网络栈。
func TestServerDepsKeepTun2socksProtocolOnly(t *testing.T) {
	deps := serverDependencyClosure(t)

	var tun2socks []string
	for dep := range deps {
		if !strings.Contains(dep, "tun2socks") {
			continue
		}
		tun2socks = append(tun2socks, dep)
		if _, ok := allowedTun2socksPackages[dep]; !ok {
			t.Errorf("服务端依赖了 %s：它不在允许清单里（只允许 SOCKS5 协议层及其缓冲池）", dep)
		}
	}
	if len(tun2socks) == 0 {
		t.Errorf("服务端依赖闭包里没有出现任何 tun2socks 包；本守卫已失效，请同步更新")
	}

	for _, forbidden := range forbiddenServerDeps {
		for dep := range deps {
			if dep == forbidden || strings.HasPrefix(dep, forbidden+"/") {
				t.Errorf("服务端依赖了 %s：它属于客户端的 TUN 实现，会把二进制显著撑大", dep)
			}
		}
	}
}

// serverDependencyClosure 返回服务端 main 包编译时用到的全部包路径，即 go list -deps 的传递闭包。
func serverDependencyClosure(t *testing.T) map[string]struct{} {
	t.Helper()

	out, err := exec.Command("go", "list", "-deps", serverPackage).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", serverPackage, err)
	}

	deps := make(map[string]struct{})
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if pkg := strings.TrimSpace(line); pkg != "" {
			deps[pkg] = struct{}{}
		}
	}
	return deps
}
