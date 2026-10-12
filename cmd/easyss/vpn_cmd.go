package main

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

// runVPNCommand 处理 "vpn" 子命令（打印或重新生成本机的 VPN 身份）。
//
// 与 "selfupdate"/"tun-helper" 一样在 flag 解析之前处理：它是"读配置 → 做一件事 →
// 退出"的工具，与代理启动共享的全局 flag（-s/-k/-l/--daemon…）没有任何交集，
// 混在一起会让 `easyss vpn identity` 也得接受一堆与它无关的参数。
//
// 返回值表示该子命令是否已被处理；若已处理，则进程已经退出。
func runVPNCommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "vpn" {
		return false
	}
	os.Exit(vpnSubcommand(os.Args[2:], os.Stdout, os.Stderr))
	return true
}

// vpnUsage 是 `easyss vpn` 的帮助文本。
//
// 写成常量是为了让 `easyss vpn`、`easyss vpn -h` 与子命令写错时看到完全一样的一
// 份说明——它同时也是"身份有两半、收件人不同"这件事唯一会被读到的文档。
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
    --dry-run  只推导将要生成的身份，不写任何文件
    --json     以 JSON 输出，便于脚本或配置工具消费

  被替换掉的旧身份备份成 <file>.bak，每次重新生成都覆盖它，因此每个文件最多只留一份
  备份，也就是「上一次生效的身份」：把它拷回原名即完成回滚。
  换地址会让每个对端的 vpn.peers[].address 失效，换 nodekey 会让对端的
  vpn.allow_clients 失效，因此必须用新值更新对端配置。
`

// vpnSubcommand 是 `easyss vpn` 的分发入口：解析子命令、加载配置、执行、返回退出码。
//
// 错误统一返回 3（而不是 1）：代理启动路径用 1，区分开能让脚本在 `easyss vpn ...`
// 失败时知道"这不是代理启动失败"。用法错误返回 2，与 flag 包的约定一致。
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

// splitVPNArgs 取出 `easyss vpn` 的子命令，并在此拦下两种用法错误：未知子命令、
// 子命令之后的多余位置参数。返回的 flags 原样交给子命令自己的 FlagSet。
//
// 判定方式是一次只认 -c/--config 的预解析，而不是"看到非 - 开头的参数就当成位置参数"
// 那种启发式：后者的取值规则与 flag 包不一致（`-c /tmp/x.json` 里的路径会被误判成位置
// 参数），而参数错误又必须发生在加载配置之前——否则一个写错的参数会先撞上"文件不存在"，
// 让人以为问题在配置上。
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
// 用一次预扫描而不是在各子命令的 flag 集里重复声明它：`easyss vpn identity --help`
// 与 `easyss vpn regen --help` 必须显示同一个 -c，而配置的加载发生在两者分派之前。
// 取值规则与 flag 包一致（-c=v、-c v、--config=v、--config v）。
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

// vpnCommonFlags 声明两个子命令共有的开关。
func vpnCommonFlags(fs *flag.FlagSet) {
	fs.String("c", "config.json", "specify config file")
	fs.String("config", "config.json", "specify config file (same as -c)")
	fs.Bool("json", false, "print the result as JSON")
}

// runVPNIdentityCmd 实现 `easyss vpn identity`。
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
	// "当前服务端不在声明列表里"只作为一行 warning：地址依然要打印出来，因为运维
	// 正需要它去配对端，而 VPN 能否工作由启动路径决定（见 runner.vpnOptions）。
	// CLI 没有运行中的会话，因此"当前服务器"就是这份配置选中的那台。
	warn := cfg.ValidateDERPServerAddr(cfg.DefaultServer().HostPort())

	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(stdout, stderr, vpnIdentityOutput(id, warn))
	}
	_, _ = fmt.Fprint(stdout, formatVPNIdentity(id, warn, vpnIdentityRegenHint()))
	return 0
}

// runVPNRegenCmd 实现 `easyss vpn regen`。
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

	// 不带选择时两个都换：`selfupdate` 默认就是"真的更新"，一条"我自己按需选择"的
	// 命令多一个必填开关只会让人先撞一次错误。
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

// writeJSON 以缩进 JSON 输出一条命令的结果。
//
// 缩进而不是紧凑输出：这个命令的读者是人（核对即将生效的地址）与配置工具各占一半，
// 而多出来的空白不会影响后者。
func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_, _ = fmt.Fprintln(stderr, "write json:", err)
		return 3
	}
	return 0
}

// vpnIdentityJSON 是 `easyss vpn identity --json` 的稳定输出契约。
//
// 字段名与配置里的字段对应（client_nodekey → vpn.allow_clients，address →
// vpn.peers[].address），使输出可以被直接粘进配置工具而不必查文档。
type vpnIdentityJSON struct {
	ClientNodeKey string   `json:"client_nodekey"`
	Address       string   `json:"address"`
	DERPNodes     []string `json:"derp_nodes"`
	// AddressError 非空表示地址不可用，原因在此；client_nodekey 仍然有效。
	AddressError string `json:"address_error,omitempty"`
	// Warning 是"VPN 在本次配置下不会工作"的说明（如当前服务端不在中继列表里）。
	Warning string `json:"warning,omitempty"`
	// HasNodeIdentity 表示地址是否来自真实存在的身份文件。false 时 address 为空、
	// 且 address_error 会说明是缺文件还是文件损坏。
	HasNodeIdentity bool `json:"has_node_identity"`
}

func vpnIdentityOutput(id *runner.VPNIdentity, warn error) vpnIdentityJSON {
	out := vpnIdentityJSON{
		ClientNodeKey:   id.ClientNodeKey,
		Address:         id.TailcatAddr,
		DERPNodes:       id.DERPNodes,
		HasNodeIdentity: id.TailcatAddr != "",
	}
	if id.AddrErr != nil {
		out.AddressError = id.AddrErr.Error()
	}
	if warn != nil {
		out.Warning = warn.Error()
	}
	return out
}

// formatVPNIdentity 是 `easyss vpn identity` 的文本输出。
//
// 输出按"一次只讲一件事"分成若干块，块之间留一个空行。这些块里的每一样东西都要被
// 人**手动复制**到对端配置里，因此可读性就是这个命令的功能本身：身份值是长 base64，
// 一块紧贴一块时很容易把中继列表当成地址的一部分复制走。
//
// 一份完整输出因此是：
//
//	<状态块：只在本机动过文件时有，见 formatVPNRegen>
//
//	client nodekey (fill the peer's vpn.allow_clients with it):
//	  nodekey:...
//
//	derp nodes in the address (region 901, tried in this order):
//	  relay-a:443, relay-b:443
//
//	node address (fill the peer's vpn.peers[].address with it; it is a secret):
//	  tc...
//
//	<附注块：warning（VPN 本会话不工作）与 regen hint，各自独立成块>
//
// regenHint 非空时追加一段提示，说明"这份身份是用哪条命令换来的、为什么对端可能还
// 拿着旧值"（见 vpnIdentityRegenHint）。
//
// 内容先攒进 builder 再一次性写出：一是只需要检查一次写错误，二是避免多行输出在
// 写一半时失败留下半截（stdout 是管道时对方可能读到截断的地址）。
func formatVPNIdentity(id *runner.VPNIdentity, derpMismatch error, regenHint string) string {
	var b strings.Builder

	fmt.Fprintln(&b, "client nodekey（填到对端的 vpn.allow_clients）:")
	fmt.Fprintln(&b, "  "+id.ClientNodeKey)

	// 中继列表在地址**之前**：它是"地址里到底有几个中继"的唯一可读来源（地址本身是
	// 一串不可读的 base64），并且与地址同属"节点地址"这件事——真正要复制到对端的是
	// 下一块里的地址，中继列表是给人核对用的。
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

// vpnIdentityRegenHint 在"本机上还有一份与当前身份不同的备份"时返回一段提示。
//
// 判据本身在 vpn.IdentityRegenPending 里（它拿得到路径、也就能被测试固定）；这里只负责
// 把结论翻译成给运维看的一句话，并说明回滚怎么做。它只提示、绝不自动重新生成：换身份
// 必须是人显式要求的动作（见 vpn.LoadOrCreate）。
func vpnIdentityRegenHint() string {
	path := vpn.NodeIdentityPath()
	if !vpn.IdentityRegenPending(path) {
		return ""
	}
	return "提示：" + path + vpn.BackupSuffix + " 里的身份与上面这份不同；" +
		"若本节点是被重新生成过的，仍拿着旧地址的对端需要用上面的地址更新" +
		"（把该备份文件拷回 " + path + " 即可回滚）。"
}

// vpnRegenJSON 是 `easyss vpn regen --json` 的稳定输出契约。
//
// old_* 三个字段是"替换前的值"，即对端配置里现在写着的那个：重新生成之后运维就是
// 拿它去对照"哪些对端要改"。
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

// formatVPNRegen 是 `easyss vpn regen` 的文本输出。
//
// 生成完必须把新身份**再打印一遍**：命令结束之后新地址就只存在于身份文件里，而运维
// 要拿它去改每个对端。旧值一并回显，因为它才是运维手上的对照物（对端配置里现在写的
// 正是它）。
//
// 与 formatVPNIdentity 同样按块组织，块间留空行。这里的块更多（状态 / 说明 / 新身份 /
// 附注 / 旧值），不分组的话一次重新生成会连出十几行，而其中最需要被看清的是"哪些文件
// 被换掉了"和"哪些对端要跟着改"这两件事——它们各自独立成块。
//
// 一份完整输出因此是：
//
//	regenerated the vpn identity; you must update every peer with the values below
//	the replaced files were backed up:
//	  <file>.bak <- <file>
//
//	client nodekey (fill the peer's vpn.allow_clients with it):
//	  nodekey:...
//
//	node address (fill the peer's vpn.peers[].address with it; it is a secret):
//	  tc...
//
//	<附注块：warning 与 regen hint，各自独立成块>
//
//	previously distributed identity (each peer still has these; replace them with the values above):
//	  nodekey:...
//	  tc...
//
// 用 res.Replaced（**实际**换掉的那一半）而不是调用方的 kinds（请求换哪一半）来判定
// 状态措辞与旧值回显：DryRun 下一半都没换，而"请求换"与"真的换了"在这两处恰好是同一个
// 问题的两个答案。
func formatVPNRegen(res *runner.VPNRegenResult, derpMismatch error) string {
	var b strings.Builder

	status := formatVPNRegenStatus(res)
	b.WriteString(status)
	fmt.Fprintln(&b)
	b.WriteString(formatVPNIdentity(res.Identity, derpMismatch, ""))

	// 旧值只在**确实变了**时回显：默认参数下两个都换，其中"地址没变"完全可能（例如中继
	// 集合没动而只是重新生成了身份——那时地址里除了公钥也确实会变，但--client 这种只换
	// 一半的情形不会）。把没变的旧值再打一遍会让"到底哪一半变了"更难看出来。
	if old := formatVPNPrevious(res); old != "" {
		fmt.Fprintln(&b)
		b.WriteString(old)
	}
	return b.String()
}

// formatVPNRegenStatus 是 regen 输出的开头：这次动了哪些文件、要不要去改对端。
//
// 它以换行结尾，由调用方决定后面隔几个空行（这里多输出一个空行的目的正是"状态与身份
// 分离"，因此不放在本函数里，避免它自身以空行结尾这种隐式约定）。
func formatVPNRegenStatus(res *runner.VPNRegenResult) string {
	var b strings.Builder

	switch {
	case res.DryRun:
		fmt.Fprintln(&b, "dry run：没有写任何文件，下面是「将要生效」的身份")
	case len(res.BackupPaths) > 0:
		fmt.Fprintln(&b, "已重新生成 VPN 身份；对端需要用下面的新值更新")
		fmt.Fprintln(&b, "被替换掉的旧身份已备份:")
		for _, path := range res.BackupPaths {
			// 备份名从结果里取而不是拼 ".bak"：打印一个并不存在的路径正好会让人找不到
			// 回滚的凭据。
			fmt.Fprintf(&b, "  %s <- %s\n", res.Backups[path], path)
		}
		// 措辞全部按**实际换掉的那一半**选（见 vpn.PeerUpdateHint / vpn.StaleSecretHint）：
		// 地址与 nodekey 的收件人是两个不同的对端字段，只换一半时提另一个字段，就是让人去
		// 改一个没变的配置。那两句话属于 vpn 包而非本命令——它们的依据是身份的语义，
		// 将来若有别的入口触发重新生成（托盘菜单等），必须说同一句话。
		//
		// 分行：第一句是"去改哪个字段"（照做就够），第二句是"不改会怎样 + 还能怎么办"。
		// 挤成一行会让人读成一句长条件状语，而它们其实是三个独立结论。
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
//
// 两半各自独立成块、各自带一句前缀，是为了看清"到底哪一半需要去对端改"：只换 client key
// 时地址那一行根本不会出现。发出去的格式故意不用"标签: 值"两行，而是一行前缀 + 缩进的
// 值——旧值是新旧对照用的，不是要复制的东西（要复制的是上面那些新值）。
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
