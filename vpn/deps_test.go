package vpn

import (
	"os/exec"
	"strings"
	"testing"
)

// TestPackageDoesNotDependOnTailcat 钉住体积不变量：本包（含传递依赖）不能引入 tailcat，
// 否则 WireGuard 引擎与 gVisor netstack 会进入只需要 DERP 中继的服务端二进制。用
// go list -deps "." 查传递依赖，而非 "./..."（vpn/node 本来就该依赖 tailcat）；实测见 docs/architecture.md 要点 19。
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
