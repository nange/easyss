package vpn

import (
	"os/exec"
	"strings"
	"testing"
)

// TestPackageDoesNotDependOnTailcat 是本包最重要的**体积不变量**：vpn 包（以及它
// 依赖的包）绝不能引入 github.com/tailscale/tailcat。
//
// 原因是可量化的：服务端二进制只需要本包的 DERP 中继（derpserver + types/key），
// 而任何对 tailcat 的引用都会把整个 WireGuard 引擎与 gVisor netstack 拖进服务端。
// 实测（darwin/arm64，-s -w）：
//
//	只引用 derpserver 的二进制   6.46 MiB
//	只引用 tailcat 的二进制     16.15 MiB
//	easyss-server 引入 tailcat 后 13.03 MiB → 27.19 MiB（+109%）
//
// 因此依赖 tailcat 的代码（节点身份、地址自检、对端面、薄中继、访问侧）全部放在
// vpn/node。这条测试用 go list 检查**传递**依赖，而不是只看本文件的 import，因为
// 后者挡不住"经由某个共享包间接引入"的情况。
//
// 注意是 "."（只查本包）而不是 "./..."：后者会连 vpn/node 一起算进来，而
// vpn/node 本来就该依赖 tailcat。
func TestPackageDoesNotDependOnTailcat(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		if _, lookErr := exec.LookPath("go"); lookErr != nil {
			t.Skip("go toolchain not in PATH")
		}
		t.Fatalf("go list -deps: %v", err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSpace(line) == "github.com/tailscale/tailcat" {
			t.Fatalf("vpn must not depend on tailcat: the server binary only needs the DERP relay, " +
				"and importing tailcat pulls the whole WireGuard engine into it (measured +14 MiB, +109%%); " +
				"move the tailcat-dependent code to vpn/node")
		}
	}
}
