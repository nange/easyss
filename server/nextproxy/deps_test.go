package nextproxy

import (
	"os/exec"
	"strings"
	"testing"
)

// 本文件钉住"服务端只借用 SOCKS5 协议层"这一依赖边界。
//
// 服务端本身不跑 tun2socks：它引用 xjasonlyu/tun2socks 只为
// transport/socks5 这一个包（客户端 SOCKS5 握手与 UDP 数据报编解码），
// 好让 next proxy 的 UDP 转发与客户端 tun2socks 对上游说同一套字节。
//
// 但 tun2socks 模块里还装着 WireGuard 引擎与 gVisor netstack——服务端一旦
// 间接引到它们，二进制会凭空长大十几 MiB（服务端与客户端的体积差异正来源于
// 此）。这条边界不是靠"别 import 错"的自觉维持的：下面按 go list 的真实依赖
// 闭包断言，任何一次不经意的间接引用都会在这里失败。
// allowedTun2socksPackages 是允许出现在服务端依赖闭包里的 tun2socks 包的**精确
// 路径**。刻意不用 "transport/" 这样的前缀：那个前缀会把 transport/shadowsocks
// 之类的实现一并放行（它同样只依赖 transport/ 下的东西），而本守卫要钉的是
// "只有 SOCKS5 协议层"。
//
// 新增任何一条都需要在这里显式登记——这正是这条守卫的目的。
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

// TestServerDepsKeepTun2socksProtocolOnly 断言服务端的依赖闭包里，tun2socks
// 只有协议层这几个包，且没有任何重量级引擎/网络栈。
//
// 用 go list 而不是源码扫描：只有真实的 import 闭包才能反映"间接引用"，
// 而这正是这种边界被破坏的方式。
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

// serverDependencyClosure 返回服务端 main 包编译时用到的全部包路径。
// go list -deps 输出的正是这份传递闭包（每行一个包），因此不需要自己去
// 遍历 imports 图。
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
