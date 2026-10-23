package vpncmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/vpn"
)

// Run 处理 "vpn" 子命令：必须在 flag 解析之前调用（与 "selfupdate"/"tun-helper" 同级），
// 它与代理启动共享的全局 flag 没有交集。返回是否已被处理；已处理时进程已经退出。
func Run() bool {
	if len(os.Args) < 2 || os.Args[1] != "vpn" {
		return false
	}
	os.Exit(vpnSubcommand(os.Args[2:], os.Stdout, os.Stderr))
	return true
}

// vpnUsage 是 `easyss vpn`、`easyss vpn -h` 与用法错误共用的唯一说明来源，三处看到的
// 必须是同一份（"身份有两半、收件人不同"只在这里说）。
const vpnUsage = `Easyss 节点组网(VPN) 工具

用法:
  easyss vpn identity [--json]                  打印本机 VPN 身份，并把值交给对端
  easyss vpn regen [--node] [--client] [flags]  重新生成本机 VPN 身份（会换掉身份本身）

identity:
  打印两样东西，它们都要填到**对端**的配置里：
    client nodekey  填到对端的 vpn.allow_clients（对端面据此识别访问侧）
    node address    填到对端的 vpn.peers[].address（内嵌 preshared key，属于秘密）
  node address 由「身份文件 + 当前 servers[] 派生出的中继集合」实时推导、不落盘，
  因此改了 servers[] 里的 derp 标记之后重新执行本命令即可，不需要重新生成。

regen:
  重新生成身份文件。不带 --node / --client 时两个都换：
    --node     重新生成 node-identity.json：地址改变，client nodekey 不变
               （对端的 vpn.peers[].address 需要更新）
    --client   重新生成 client.key：client nodekey 改变，地址不变
               （对端的 vpn.allow_clients 需要更新）
    --dry-run  只预览一份新身份，不写任何文件（真写时会重新生成密钥，地址会不同）
    --json     以 JSON 输出，便于脚本或配置工具消费

  被替换掉的旧身份备份成 <file>.bak，每次重新生成都覆盖它，因此每个文件最多只留一份
  备份，也就是「上一次生效的身份」：把它拷回原名即完成回滚。
  换地址会让每个对端的 vpn.peers[].address 失效，换 nodekey 会让对端的
  vpn.allow_clients 失效，因此必须用新值更新对端配置。
`

// vpnSubcommand 是 `easyss vpn` 的分发入口。
//
// 错误返回 3、用法错误返回 2（flag 包的约定）：1 留给代理启动失败，脚本靠退出码区分。
func vpnSubcommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, vpnUsage)
		return 2
	}

	// 参数（含 -c/--json 与位置参数）必须在加载配置之前判定：一个写错的参数不该先
	// 撞上"文件不存在"，否则用户会以为问题在配置上。
	sub, flags, ok := splitVPNArgs(args)
	if !ok {
		_, _ = fmt.Fprint(stderr, vpnUsage)
		return 2
	}
	switch sub {
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(stdout, vpnUsage)
		return 0
	}

	// 状态文件、config.json 与 peer.txt 都定位到"可执行文件旁边"，与代理启动时的
	// 路径解析保持同一套（见 util.ResolvePath 对 macOS .app bundle 的处理）。
	cfg, err := config.LoadConfig(util.ResolvePath(vpnConfigFlag(flags)))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "vpn:", err)
		return 3
	}
	cfg.ResolveFilePaths()

	switch sub {
	case "identity":
		return runVPNIdentityCmd(cfg, flags, stdout, stderr)
	default:
		return runVPNRegenCmd(cfg, flags, stdout, stderr)
	}
}

// splitVPNArgs 取出子命令并拦下用法错误；返回的 flags 原样交给子命令自己的 FlagSet。
// 参数错误必须早于配置加载（否则会先撞上"文件不存在"），且取值规则要与 flag 包一致：
// `-c /tmp/x.json` 里的路径不能被当成位置参数。
func splitVPNArgs(args []string) (sub string, flags []string, ok bool) {
	if len(args) == 0 {
		return "", nil, false
	}
	sub, flags = args[0], args[1:]
	switch sub {
	case "-h", "-help", "--help", "help":
		return sub, nil, true
	case "identity", "regen":
	default:
		return sub, nil, false
	}

	// Parse 会把位置参数留在 Args() 里，也会把 --json 这类"本层不认、子命令认"的
	// 开关原样留下（本层只声明了配置路径，其余开关一概不解析）。
	fs := flag.NewFlagSet("vpn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("c", "config.json", "")
	fs.String("config", "config.json", "")
	fs.Bool("json", false, "")
	fs.Bool("node", false, "")
	fs.Bool("client", false, "")
	fs.Bool("dry-run", false, "")
	if err := fs.Parse(flags); err != nil || fs.NArg() > 0 {
		return sub, nil, false
	}
	return sub, flags, true
}

// vpnConfigFlag 从子命令参数里取出 -c/--config 的值。
//
// 配置在两个子命令分派之前加载，因此只能预扫描；取值规则必须与 flag 包一致。
func vpnConfigFlag(args []string) string {
	const def = "config.json"
	for i := range len(args) {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch name {
		case "-c", "--config":
			if hasValue {
				return value
			}
			if i+1 < len(args) {
				return args[i+1]
			}
			return def
		}
	}
	return def
}

func vpnCommonFlags(fs *flag.FlagSet) {
	fs.String("c", "config.json", "specify config file")
	fs.String("config", "config.json", "specify config file (same as -c)")
	fs.Bool("json", false, "print the result as JSON")
}

func runVPNIdentityCmd(cfg *config.ClientConfig, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vpn identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, vpnUsage) }
	vpnCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "vpn identity: unexpected argument %q\n\n%s", fs.Arg(0), vpnUsage)
		return 2
	}

	id, err := runner.LoadVPNIdentity(cfg)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "vpn identity:", err)
		return 3
	}
	// "当前服务端不在声明列表里"只作一行 warning：地址仍要照常打印（运维正需要它去配
	// 对端），VPN 能否工作由启动路径决定（见 runner.vpnOptions）。
	warn := cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort())

	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(stdout, stderr, vpnIdentityOutput(id, warn))
	}
	_, _ = fmt.Fprint(stdout, formatVPNIdentity(id, warn, vpnIdentityRegenHint()))
	return 0
}

func runVPNRegenCmd(cfg *config.ClientConfig, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vpn regen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, vpnUsage) }
	vpnCommonFlags(fs)
	node := fs.Bool("node", false, "regenerate the node identity (the node address changes)")
	client := fs.Bool("client", false, "regenerate the client key (the client nodekey changes)")
	dryRun := fs.Bool("dry-run", false, "show what would be generated without writing any file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "vpn regen: unexpected argument %q\n\n%s", fs.Arg(0), vpnUsage)
		return 2
	}

	kinds := runner.VPNKeyKind(0)
	if *node {
		kinds |= runner.RegenNodeIdentity
	}
	if *client {
		kinds |= runner.RegenClientKey
	}
	if kinds == 0 {
		kinds = runner.RegenNodeIdentity | runner.RegenClientKey
	}

	res, err := runner.RegenerateVPNIdentity(cfg, runner.VPNRegenOptions{
		Kinds:  kinds,
		DryRun: *dryRun,
	})
	if err != nil {
		// 出错时把已经改过的文件说明白：重新生成是多文件的动作，失败可能发生在
		// 第一份文件已经落盘之后，而"哪些对端需要改"取决于到底换了哪一半。
		_, _ = fmt.Fprintln(stderr, "vpn regen:", err)
		if res != nil {
			for _, path := range res.BackupPaths {
				_, _ = fmt.Fprintf(stderr, "  %s was replaced (backup: %s)\n", path, res.Backups[path])
			}
		}
		return 3
	}

	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(stdout, stderr, vpnRegenOutput(res, cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort())))
	}
	_, _ = fmt.Fprint(stdout, formatVPNRegen(res, cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort())))
	return 0
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_, _ = fmt.Fprintln(stderr, "write json:", err)
		return 3
	}
	return 0
}

// vpnIdentityJSON 是 `easyss vpn identity --json` 的稳定输出契约：字段名与配置字段对应
// （client_nodekey → vpn.allow_clients，address → vpn.peers[].address），不能改。
type vpnIdentityJSON struct {
	ClientNodeKey string   `json:"client_nodekey"`
	Address       string   `json:"address"`
	DERPNodes     []string `json:"derp_nodes"`
	// AddressError 非空表示地址不可用，原因在此；client_nodekey 仍然有效。
	AddressError string `json:"address_error,omitempty"`
	// Warning 是"VPN 在本次配置下不会工作"的说明（如当前服务端不在中继列表里）。
	Warning string `json:"warning,omitempty"`
	// HasNodeIdentity 只看身份文件是否可读：false 表示缺文件或文件损坏（此时 address 必然为空）。
	// address 为空也可能只是中继列表推不出来，那由 AddressError 说明。
	HasNodeIdentity bool `json:"has_node_identity"`
}

func vpnIdentityOutput(id *runner.VPNIdentity, warn error) vpnIdentityJSON {
	out := vpnIdentityJSON{
		ClientNodeKey:   id.ClientNodeKey,
		Address:         id.TailcatAddr,
		DERPNodes:       id.DERPNodes,
		HasNodeIdentity: id.HasNodeIdentity,
	}
	if id.AddrErr != nil {
		out.AddressError = id.AddrErr.Error()
	}
	if warn != nil {
		out.Warning = warn.Error()
	}
	return out
}

// formatVPNIdentity 是 `easyss vpn identity` 的文本输出；块间必须有空行——这些值都要人手
// 复制，粘连时会把中继列表当成地址的一部分复制走（格式契约见 docs/architecture.md 要点 19）。
// 内容先攒进 builder 再一次性写出：stdout 是管道时，半截输出会让对方读到截断的地址。
func formatVPNIdentity(id *runner.VPNIdentity, derpMismatch error, regenHint string) string {
	var b strings.Builder

	fmt.Fprintln(&b, "client nodekey（填到对端的 vpn.allow_clients）:")
	fmt.Fprintln(&b, "  "+id.ClientNodeKey)

	// 中继列表在地址**之前**：地址是不可读的 base64，它是"地址里到底有几个中继"的唯一
	// 可读来源，而真正要复制到对端的是下一块里的地址。
	if id.AddrErr == nil {
		fmt.Fprintf(&b, "\n地址内嵌的 derp 节点（region %d，按此顺序尝试）:\n", vpn.RegionID)
		fmt.Fprintln(&b, "  "+strings.Join(id.DERPNodes, ", "))
	}

	fmt.Fprintln(&b)
	if id.AddrErr != nil {
		fmt.Fprintln(&b, "node address（填到对端的 vpn.peers[].address）: 不可用")
		fmt.Fprintln(&b, "  原因: "+id.AddrErr.Error())
	} else {
		fmt.Fprintln(&b, "node address（填到对端的 vpn.peers[].address；属于秘密）:")
		fmt.Fprintln(&b, "  "+id.TailcatAddr)
	}

	// 两条附注各自独立成块。它们都不影响上面那些值能不能复制，因此不能与身份值贴在
	// 一起——那会让人以为地址本身有问题。
	if derpMismatch != nil {
		// 不是致命错误：地址本身仍然是对的，运维正需要它去配对端。但这台节点上
		// VPN 不会工作（见 runner.vpnOptions 的门禁），所以必须当场说出来。
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "注意：当前配置下本节点上的 VPN 不会工作: "+derpMismatch.Error())
	}
	if regenHint != "" {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, regenHint)
	}
	return b.String()
}

// vpnIdentityRegenHint 只在备份与当前身份不同（vpn.IdentityRegenPending）时给出回滚办法；
// 它绝不自动重新生成——换身份必须是人显式要求的动作（见 vpn.LoadOrCreate）。
func vpnIdentityRegenHint() string {
	path := vpn.NodeIdentityPath()
	if !vpn.IdentityRegenPending(path) {
		return ""
	}
	return "提示：" + path + vpn.BackupSuffix + " 里的身份与上面这份不同；" +
		"若本节点是被重新生成过的，仍拿着旧地址的对端需要用上面的地址更新" +
		"（把该备份文件拷回 " + path + " 即可回滚）。"
}

// vpnRegenJSON 是 `easyss vpn regen --json` 的稳定输出契约：old_* 是替换前的值，即对端
// 配置里现在写着的那个，运维拿它对照"哪些对端要改"。
type vpnRegenJSON struct {
	DryRun           bool              `json:"dry_run"`
	ClientNodeKey    string            `json:"client_nodekey"`
	Address          string            `json:"address"`
	DERPNodes        []string          `json:"derp_nodes"`
	AddressError     string            `json:"address_error,omitempty"`
	Warning          string            `json:"warning,omitempty"`
	OldClientNodeKey string            `json:"old_client_nodekey,omitempty"`
	OldAddress       string            `json:"old_address,omitempty"`
	Backups          map[string]string `json:"backups,omitempty"`
}

func vpnRegenOutput(res *runner.VPNRegenResult, warn error) vpnRegenJSON {
	id := res.Identity
	out := vpnRegenJSON{
		DryRun:           res.DryRun,
		ClientNodeKey:    id.ClientNodeKey,
		Address:          id.TailcatAddr,
		DERPNodes:        id.DERPNodes,
		OldClientNodeKey: res.OldClientNodeKey,
		OldAddress:       res.OldTailcatAddr,
		Backups:          res.Backups,
	}
	if id.AddrErr != nil {
		out.AddressError = id.AddrErr.Error()
	}
	if warn != nil {
		out.Warning = warn.Error()
	}
	return out
}

// formatVPNRegen 是 `easyss vpn regen` 的文本输出：新身份必须再打印一遍（命令结束后新地址
// 只存在于身份文件里），旧值一并回显作对照；措辞与旧值都按 res.Replaced（实际换掉的那一半）
// 而不是请求的 Kinds 选（格式契约见 docs/architecture.md 要点 19）。
func formatVPNRegen(res *runner.VPNRegenResult, derpMismatch error) string {
	var b strings.Builder

	status := formatVPNRegenStatus(res)
	b.WriteString(status)
	fmt.Fprintln(&b)
	b.WriteString(formatVPNIdentity(res.Identity, derpMismatch, ""))

	// 旧值只在**确实变了**时回显：没变的那一半再打一遍，会让"到底哪一半需要去改"更难看出。
	if old := formatVPNPrevious(res); old != "" {
		fmt.Fprintln(&b)
		b.WriteString(old)
	}
	return b.String()
}

// formatVPNRegenStatus 以单个换行结尾、不带尾部空行：块间空行由调用方决定。
func formatVPNRegenStatus(res *runner.VPNRegenResult) string {
	var b strings.Builder

	switch {
	case res.DryRun:
		fmt.Fprintln(&b, "dry run：没有写任何文件；下面是一份新身份的预览（真写时会重新生成密钥，地址会不同）")
	case len(res.BackupPaths) > 0:
		fmt.Fprintln(&b, "已重新生成 VPN 身份；对端需要用下面的新值更新")
		fmt.Fprintln(&b, "被替换掉的旧身份已备份:")
		for _, path := range res.BackupPaths {
			// 备份名从结果里取而不是拼 ".bak"：打印一个并不存在的路径正好会让人找不到
			// 回滚的凭据。
			fmt.Fprintf(&b, "  %s <- %s\n", res.Backups[path], path)
		}
		// 措辞按 res.Replaced 选：地址与 nodekey 的收件人是两个不同的对端字段，提错字段
		// 就是让人去改一个没变的配置。这些句子属于 vpn 包——别的入口触发重新生成时必须
		// 说同一句话。
		fmt.Fprintln(&b, vpn.PeerUpdateHint(res.Replaced))
		for _, line := range vpn.ConsequenceHint(res.Replaced) {
			fmt.Fprintln(&b, "  "+line)
		}
	default:
		// 这台节点还没有身份（或身份文件缺失），因此没有任何文件被替换：下面的值仍然
		// 要复制给对端，只是不需要"更新"。
		fmt.Fprintln(&b, "已生成 VPN 身份（此前没有身份文件，没有可替换的东西）")
	}
	return b.String()
}

// formatVPNPrevious 是 regen 输出的收尾：对端手里还拿着的那份旧身份。
// 两半各自成块（只换一半时另一行不出现），且不用"标签: 值"格式——旧值是对照物，不是要复制的东西。
func formatVPNPrevious(res *runner.VPNRegenResult) string {
	oldNodeKey, oldAddr := "", ""
	if res.Replaced&runner.RegenClientKey != 0 && res.OldClientNodeKey != "" && res.OldClientNodeKey != res.Identity.ClientNodeKey {
		oldNodeKey = res.OldClientNodeKey
	}
	if res.Replaced&runner.RegenNodeIdentity != 0 && res.OldTailcatAddr != "" && res.OldTailcatAddr != res.Identity.TailcatAddr {
		oldAddr = res.OldTailcatAddr
	}
	if oldNodeKey == "" && oldAddr == "" {
		return ""
	}

	var b strings.Builder
	fmt.Fprintln(&b, "旧身份（各对端配置里仍是这些值，请替换成上面那些）:")
	if oldNodeKey != "" {
		fmt.Fprintln(&b, "  旧 "+oldNodeKey+"  (对端的 "+vpn.RecipientNodeKey+")")
	}
	if oldAddr != "" {
		fmt.Fprintln(&b, "  旧 "+oldAddr+"  (对端的 "+vpn.RecipientAddress+")")
	}
	return b.String()
}
