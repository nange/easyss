package vpncmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/vpn"
)

// wantLines 断言输出的**逐行结构**，包括空行位置：空行是这三个命令可读性的全部来源，
// 字符级 Contains 断言看不见它，而"挤成一堆"正是这条输出被改掉的方式。
func wantLines(t *testing.T, out string, want ...string) {
	t.Helper()
	got := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if slices.Equal(got, want) {
		return
	}
	var b strings.Builder
	for _, line := range got {
		fmt.Fprintf(&b, "    %q\n", line)
	}
	t.Errorf("output lines differ from the contract:\n%s", b.String())
}

// hints 展开状态块里的提示行；期望值取自 vpn 包的同一对函数，因此比的是"按实际换掉的
// 那一半选文案"这条契约，而不是文案本身。
func hints(replaced runner.VPNKeyKind) []string {
	lines := []string{vpn.PeerUpdateHint(replaced)}
	for _, line := range vpn.ConsequenceHint(replaced) {
		lines = append(lines, "  "+line)
	}
	return lines
}

// TestFormatVPNIdentity 固定 `easyss vpn identity` 的输出契约：身份、中继列表、地址各成块
// 且块间空行（这些值要人手复制，粘连时会把中继列表一起复制走）；附注独立成块，不影响地址
// 本身可用。文案是中文，但配置字段名、命令名与 flag 保持原文（运维要拿它们去搜配置）。
func TestFormatVPNIdentity(t *testing.T) {
	id := &runner.VPNIdentity{
		ClientNodeKey: "nodekey:abc",
		TailcatAddr:   "tcFULLADDRESS",
		DERPNodes:     []string{"relay-a.example.com:443", "relay-b.example.com:8443"},
	}

	t.Run("没有附注时只有身份三块", func(t *testing.T) {
		wantLines(t, formatVPNIdentity(id, nil, ""), []string{
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:abc",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443, relay-b.example.com:8443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcFULLADDRESS",
		}...)
	})

	t.Run("warning 与 hint 各自独立成块且不与其他行粘连", func(t *testing.T) {
		out := formatVPNIdentity(id,
			errors.New("the current server c.example.com:443 is not one of the DERP relays"),
			"提示：备份里的身份与上面这份不同")
		wantLines(t, out, []string{
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:abc",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443, relay-b.example.com:8443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcFULLADDRESS",
			"",
			"注意：当前配置下本节点上的 VPN 不会工作: " +
				"the current server c.example.com:443 is not one of the DERP relays",
			"",
			"提示：备份里的身份与上面这份不同",
		}...)
	})

	t.Run("推导不出地址时不打印中继块，但仍保留地址块与原因", func(t *testing.T) {
		broken := &runner.VPNIdentity{ClientNodeKey: "nodekey:abc", AddrErr: errors.New("no DERP relay is declared")}
		wantLines(t, formatVPNIdentity(broken, nil, ""), []string{
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:abc",
			"",
			"node address（填到对端的 vpn.peers[].address）: 不可用",
			"  原因: no DERP relay is declared",
		}...)
	})
}

// newVPNIdentity 是本文件里 regen 输出用例共用的"新身份"。
func newVPNIdentity() *runner.VPNIdentity {
	return &runner.VPNIdentity{
		ClientNodeKey: "nodekey:new",
		TailcatAddr:   "tcNEWADDRESS",
		DERPNodes:     []string{"relay-a.example.com:443"},
	}
}

// TestFormatVPNRegen 固定 `easyss vpn regen` 的输出契约：状态块在最前；新身份必须再打印
// 一遍（结束后新地址只存在于身份文件里）；旧值单独成块，且只含**确实被换掉**的那一半——
// 把没变的地址回显成"previous"会让"哪一半要改"变成一道判断题。
func TestFormatVPNRegen(t *testing.T) {
	replaced := &runner.VPNRegenResult{
		Identity:         newVPNIdentity(),
		Replaced:         runner.RegenNodeIdentity | runner.RegenClientKey,
		OldClientNodeKey: "nodekey:old",
		OldTailcatAddr:   "tcOLDADDRESS",
		Backups: map[string]string{
			"/state/client.key":         "/state/client.key.bak",
			"/state/node-identity.json": "/state/node-identity.json.bak",
		},
		BackupPaths: []string{"/state/client.key", "/state/node-identity.json"},
	}

	t.Run("两个都换：状态块 + 新身份 + 两个旧值", func(t *testing.T) {
		want := slices.Concat([]string{
			"已重新生成 VPN 身份；对端需要用下面的新值更新",
			"被替换掉的旧身份已备份:",
			"  /state/client.key.bak <- /state/client.key",
			"  /state/node-identity.json.bak <- /state/node-identity.json",
		}, hints(runner.RegenNodeIdentity|runner.RegenClientKey), []string{
			"",
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:new",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcNEWADDRESS",
			"",
			"旧身份（各对端配置里仍是这些值，请替换成上面那些）:",
			"  旧 nodekey:old  (对端的 " + vpn.RecipientNodeKey + ")",
			"  旧 tcOLDADDRESS  (对端的 " + vpn.RecipientAddress + ")",
		})
		wantLines(t, formatVPNRegen(replaced, nil), want...)
	})

	t.Run("只换 client key 时不出现旧地址那一行，后果只说白名单", func(t *testing.T) {
		onlyClient := *replaced
		onlyClient.Replaced = runner.RegenClientKey
		onlyClient.BackupPaths = []string{"/state/client.key"}
		onlyClient.Backups = map[string]string{"/state/client.key": "/state/client.key.bak"}

		out := formatVPNRegen(&onlyClient, nil)
		want := slices.Concat([]string{
			"已重新生成 VPN 身份；对端需要用下面的新值更新",
			"被替换掉的旧身份已备份:",
			"  /state/client.key.bak <- /state/client.key",
		}, hints(runner.RegenClientKey), []string{
			"",
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:new",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcNEWADDRESS",
			"",
			"旧身份（各对端配置里仍是这些值，请替换成上面那些）:",
			"  旧 nodekey:old  (对端的 " + vpn.RecipientNodeKey + ")",
		})
		wantLines(t, out, want...)

		// 地址没变，因此**提示**里不该出现它的收件人字段（那会让人去改一个没变的配置）。
		// 只在提示块里查：地址本身当然要照常打印，它只是不该被说成"旧的"。
		if tail, ok := strings.CutPrefix(out, strings.Join(want[:3], "\n")); ok {
			if head, _, found := strings.Cut(tail, "\n\nclient nodekey（填到对端的 vpn.allow_clients）:"); found && strings.Contains(head, vpn.RecipientAddress) {
				t.Errorf("the note mentions the address recipient although the address did not change: %q", head)
			}
		}
	})

	t.Run("dry run 明确说明没有写文件，也不提备份与旧值", func(t *testing.T) {
		dry := *replaced
		dry.DryRun = true
		dry.Replaced = 0
		dry.BackupPaths = nil
		wantLines(t, formatVPNRegen(&dry, nil), []string{
			"dry run：没有写任何文件；下面是一份新身份的预览（真写时会重新生成密钥，地址会不同）",
			"",
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:new",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcNEWADDRESS",
		}...)
	})

	t.Run("没有可替换的文件时不提备份与旧值", func(t *testing.T) {
		fresh := &runner.VPNRegenResult{Identity: newVPNIdentity(), Backups: map[string]string{}}
		wantLines(t, formatVPNRegen(fresh, nil), []string{
			"已生成 VPN 身份（此前没有身份文件，没有可替换的东西）",
			"",
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:new",
			"",
			"地址内嵌的 derp 节点（region 901，按此顺序尝试）:",
			"  relay-a.example.com:443",
			"",
			"node address（填到对端的 vpn.peers[].address；属于秘密）:",
			"  tcNEWADDRESS",
		}...)
	})

	t.Run("新身份算不出地址时状态块与原因都保留且不粘连", func(t *testing.T) {
		broken := *replaced
		broken.Identity = &runner.VPNIdentity{ClientNodeKey: "nodekey:new", AddrErr: errors.New("no DERP relay is declared")}
		broken.OldTailcatAddr = ""

		want := slices.Concat([]string{
			"已重新生成 VPN 身份；对端需要用下面的新值更新",
			"被替换掉的旧身份已备份:",
			"  /state/client.key.bak <- /state/client.key",
			"  /state/node-identity.json.bak <- /state/node-identity.json",
		}, hints(runner.RegenNodeIdentity|runner.RegenClientKey), []string{
			"",
			"client nodekey（填到对端的 vpn.allow_clients）:",
			"  nodekey:new",
			"",
			"node address（填到对端的 vpn.peers[].address）: 不可用",
			"  原因: no DERP relay is declared",
			"",
			"旧身份（各对端配置里仍是这些值，请替换成上面那些）:",
			"  旧 nodekey:old  (对端的 " + vpn.RecipientNodeKey + ")",
		})
		wantLines(t, formatVPNRegen(&broken, nil), want...)
	})

	t.Run("无法写入时不打印任何身份值", func(t *testing.T) {
		// 出错路径（见 runner.RegenerateVPNIdentity）不会有 Identity，调用方也不该调这个
		// 函数；这里固定的是"两者都没有时输出不 panic、也不编造内容"。
		empty := &runner.VPNRegenResult{Backups: map[string]string{}, Identity: &runner.VPNIdentity{AddrErr: errors.New("x")}}
		out := formatVPNRegen(empty, nil)
		if out == "" {
			t.Error("output is empty")
		}
	})
}

// TestVPNRegenOutputJSON 固定 `--json` 的字段：脚本与配置工具靠它把新值填进对端，因此
// 字段名要与配置里的字段对应，且"地址不可用"必须与"地址为空"区分开。
func TestVPNRegenOutputJSON(t *testing.T) {
	res := &runner.VPNRegenResult{
		Identity:         newVPNIdentity(),
		Replaced:         runner.RegenNodeIdentity | runner.RegenClientKey,
		OldClientNodeKey: "nodekey:old",
		OldTailcatAddr:   "tcOLDADDRESS",
		Backups:          map[string]string{"/state/client.key": "/state/client.key.bak"},
	}

	b, err := json.Marshal(vpnRegenOutput(res, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"client_nodekey":"nodekey:new"`,
		`"address":"tcNEWADDRESS"`,
		`"old_address":"tcOLDADDRESS"`,
		`"old_client_nodekey":"nodekey:old"`,
		`"derp_nodes":["relay-a.example.com:443"]`,
		`"dry_run":false`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("json %s should contain %s", b, want)
		}
	}
	if strings.Contains(string(b), "address_error") {
		t.Errorf("json %s carries an address_error although the address is usable", b)
	}

	broken := *res
	broken.Identity = &runner.VPNIdentity{ClientNodeKey: "nodekey:new", AddrErr: errors.New("no DERP relay is declared")}
	b, err = json.Marshal(vpnRegenOutput(&broken, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "no DERP relay is declared") {
		t.Errorf("json %s should explain why the address is unavailable", b)
	}
}

func TestVPNIdentityOutputJSON(t *testing.T) {
	id := &runner.VPNIdentity{
		ClientNodeKey:   "nodekey:abc",
		TailcatAddr:     "tcFULLADDRESS",
		DERPNodes:       []string{"relay-a.example.com:443"},
		HasNodeIdentity: true,
	}
	b, err := json.Marshal(vpnIdentityOutput(id, errors.New("the current server is not a relay")))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"client_nodekey":"nodekey:abc"`,
		`"address":"tcFULLADDRESS"`,
		`"warning":"the current server is not a relay"`,
		`"has_node_identity":true`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("json %s should contain %s", b, want)
		}
	}

	// 身份文件可读、只是中继列表推不出地址：has_node_identity 必须为 true，原因在 address_error。
	noAddr := &runner.VPNIdentity{
		ClientNodeKey:   "nodekey:abc",
		HasNodeIdentity: true,
		AddrErr:         errors.New("no DERP relay is declared"),
	}
	b, err = json.Marshal(vpnIdentityOutput(noAddr, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"has_node_identity":true`) {
		t.Errorf("json %s should report the identity file is readable even without an address", b)
	}
	if !strings.Contains(string(b), "no DERP relay is declared") {
		t.Errorf("json %s should explain why the address is unavailable", b)
	}

	// 身份文件缺失/损坏：has_node_identity 为 false。
	missing := &runner.VPNIdentity{AddrErr: errors.New("cannot read the node identity")}
	b, err = json.Marshal(vpnIdentityOutput(missing, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"has_node_identity":false`) {
		t.Errorf("json %s should report the missing identity file", b)
	}
}

// TestVPNSubcommandUsage 固定用法错误被拒绝，且判定发生在加载配置之前：一个写错的参数
// 不该先撞上"文件不存在"。
func TestVPNSubcommandUsage(t *testing.T) {
	t.Run("没有子命令时给出用法并失败", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := vpnSubcommand(nil, &out, &errOut); code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "easyss vpn regen") {
			t.Errorf("stderr %q should show the usage", errOut.String())
		}
	})

	t.Run("未知子命令被拒绝", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := vpnSubcommand([]string{"identify"}, &out, &errOut); code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "easyss vpn identity") {
			t.Errorf("stderr %q should show the usage", errOut.String())
		}
	})

	t.Run("-h 打印用法且成功", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := vpnSubcommand([]string{"-h"}, &out, &errOut); code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if !strings.Contains(out.String(), "--dry-run") {
			t.Errorf("stdout %q should document --dry-run", out.String())
		}
	})

	t.Run("配置缺失时退出码是 3 而不是 1", func(t *testing.T) {
		var out, errOut strings.Builder
		code := vpnSubcommand([]string{"identity", "-c", filepath.Join(t.TempDir(), "missing.json")}, &out, &errOut)
		if code != 3 {
			t.Errorf("exit code = %d, want 3 (1 is reserved for a failed proxy start)", code)
		}
	})

	t.Run("多余的位置参数被拒绝", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := vpnSubcommand([]string{"identity", "extra"}, &out, &errOut); code != 2 {
			t.Errorf("exit code = %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "easyss vpn regen") {
			t.Errorf("stderr %q should show the usage", errOut.String())
		}
	})
}

// TestVPNConfigFlag 固定 -c 的取值规则：它与 flag 包一致（-c=v、-c v、--config=v），因为
// 配置必须在子命令分派之前加载，只能由预扫描取值。
func TestVPNConfigFlag(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, "config.json"},
		{[]string{"--json"}, "config.json"},
		{[]string{"-c", "/tmp/a.json"}, "/tmp/a.json"},
		{[]string{"-c=/tmp/b.json", "--json"}, "/tmp/b.json"},
		{[]string{"--json", "--config", "/tmp/c.json"}, "/tmp/c.json"},
		{[]string{"--config=/tmp/d.json"}, "/tmp/d.json"},
		{[]string{"-c"}, "config.json"}, // 缺值：退回默认值，由加载器报"文件不存在"
	}
	for _, tc := range cases {
		if got := vpnConfigFlag(tc.args); got != tc.want {
			t.Errorf("vpnConfigFlag(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}
