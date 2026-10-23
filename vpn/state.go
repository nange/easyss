package vpn

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/util"
)

// VPN 状态目录名（相对可执行文件目录）。三份长期密钥与对端面地址文件都放在
// 这里，使"备份/迁移一个节点"只需带走一个目录。
//
// 本文件只依赖 tailscale.com/types/key：它同时被服务端（DERP 私钥）与 vpn/node
// 使用，因此绝不能引入 tailcat——那会把整个 WireGuard 引擎拖进只需要跑 DERP
// 中继的服务端二进制。
const StateDirName = "vpn"

// StateDir 返回 VPN 状态目录 <exe>/vpn。
//
// 用可执行文件目录而不是 XDG 配置目录：easyss 的 config.json 与日志本来就与
// 二进制同目录（见 util.CurrentDir 对 macOS .app bundle 的处理），密钥放在
// 同一处才不会出现"配置搬走了、密钥没搬"的错位。
func StateDir() string {
	return filepath.Join(util.CurrentDir(), StateDirName)
}

// NodeIdentityPath 返回 tailcat 服务端身份的文件路径。
func NodeIdentityPath() string { return filepath.Join(StateDir(), "node-identity.json") }

// ClientKeyPath 返回访问侧 client 私钥的文件路径。
//
// 它必须跨重启稳定：`vpn.allow_clients` 里的白名单是按 node key 匹配的，
// 每次重启换一把新 key 会让白名单立刻失效。
func ClientKeyPath() string { return filepath.Join(StateDir(), "client.key") }

// DERPKeyPath 返回内嵌 DERP 中继私钥的文件路径。
func DERPKeyPath() string { return filepath.Join(StateDir(), "derp.key") }

// NodeKeyString 返回本 node 私钥对应的公钥文本（"nodekey:<hex>"），即
// `vpn.allow_clients` 里要填的那串东西。启动日志用它，使运维不必去猜白名单格式。
func NodeKeyString(k key.NodePrivate) string {
	return k.Public().String()
}

// LoadOrCreateKey 读取 path 里的 node 私钥；文件不存在时生成一个并落盘。
//
// 访问侧 client key 与 DERP 私钥都用它，只是路径不同——两者的共同要求都是
// "跨重启稳定"。文件以 0600 写入、目录 0700，并先写临时文件再 rename：崩溃留下
// 一个截断的文件会在下一次启动被当成"损坏"，而损坏的代价是重新生成密钥，
// 也就是所有对端都要重新配置。
func LoadOrCreateKey(path string) (key.NodePrivate, error) {
	var k key.NodePrivate
	err := LoadOrCreate(path, "node key",
		func() ([]byte, error) {
			// 与 tailcat 的 genkey 一致，写成一行带前缀的文本。
			return key.NewNode().MarshalText()
		},
		func(data []byte) error { return k.UnmarshalText(bytes.TrimSpace(data)) },
	)
	if err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// LoadOrCreate 实现"读不到就生成"的统一语义：
//
//   - 文件存在但无法解析 → 报错，**绝不静默覆盖**（覆盖等于换掉身份，而所有对端
//     的配置都要跟着改，必须由人决定，所以这里只把该跑哪条命令告诉运维）；
//   - 文件不存在 → 用 create 生成内容、以 0600 原子写入；
//   - 其他读取错误（权限等）→ 原样报错，不要伪装成"文件不存在"。
func LoadOrCreate(path, what string, create func() ([]byte, error), load func([]byte) error) error {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := load(data); err != nil {
			return fmt.Errorf("vpn: %s: corrupt %s: %w (%s, but every peer will need the new address)", path, what, err, RegenHint)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("vpn: read %s: %w", path, err)
	}

	content, err := create()
	if err != nil {
		return fmt.Errorf("vpn: generate %s: %w", what, err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("vpn: create state dir %s: %w", dir, err)
		}
	}
	// 先写临时文件再 rename：任何中途失败都不会留下一个"看起来存在但内容不全"
	// 的密钥文件。
	if err := writeFileAtomic(path, content); err != nil {
		return err
	}
	// 新建之后必须把内容读回调用方：两条路径（读既有文件 / 刚生成）返回的身份
	// 必须来自同一份字节，否则"新建时拿到零值"这类错误只会在首次启动时出现。
	return load(content)
}

// BackupSuffix 是 RegenerateFile 为被替换掉的身份文件写出的备份后缀。
//
// 每个身份文件**最多只留一份**备份（固定名 `<path>.bak`）：它就是"上一次生效的身份"，
// 也是重新生成之后的回滚点与新旧对照物。刻意不保留更早的那几份——同一台节点上的历史
// 身份没有用途（对端只会用其中一个地址），却会让状态目录随时间稳定增长，并把"该拿哪份
// 去回滚"变成一个需要判断的问题。每次重新生成都用本次的旧身份覆盖它，因此备份永远对应
// "最后一个被替换掉的身份"。
const BackupSuffix = ".bak"

// IdentityRegenPending 报告"当前身份与它的备份不同"，即这台节点被重新生成过、而备份
// 里那份旧身份（连同旧地址）可能仍被某些对端使用者。
//
// 判据是**内容**而不是修改时间：备份每次重新生成都会被本次的旧身份覆盖，因此"两份内容
// 不同"恰好等价于"当前生效的是重新生成出来的那份"。mtime 判据有两个脆点——备份与身份
// 文件在同一次操作里先后写入，时间戳只差微秒；而"拷回备份去回滚"之后 mtime 甚至可能
// 反向——内容比较不受这些影响，也不会因为一次 cp/rsync 就误报。
//
// 它只回答"要不要提醒"，不做任何判断之外的写入；任何读取失败（含备份还不存在）都返回
// false，因为一条提示不值得让调用命令失败。
func IdentityRegenPending(path string) bool {
	current, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	backup, err := os.ReadFile(path + BackupSuffix)
	if err != nil {
		return false
	}
	return !bytes.Equal(current, backup)
}

// RegenHint 告诉运维身份文件损坏或需要轮换时该跑哪条命令。
//
// 它由本包导出，因为最需要这句话的地方在调用方：`runner` 把身份文件读不出来这件事
// 变成地址那半的失败原因（"cannot read the node identity: ..."），而修法只有这一条命令。
// LoadOrCreate 的坏文件错误内联了同一句话（那里要能独立读懂，不依赖常量名）。
const RegenHint = "run \"easyss vpn regen\" to regenerate it"

// KeyKind 指定重写哪一半身份。它的位掩码形态让调用方可以直接组合（两个都换 = 两者相或），
// 而 VPN 身份恰好就是这两半，没有第三半。
//
// 定义在本包而不是命令行或 runner 层，是因为每一半的**收件人**（对端的哪个配置字段）与
// **代价**（改不对会怎样）都是身份的属性：提示文案、旧值回显都要用同一份判断，分处两处
// 必然会漂移——只换一半时提到另一个字段，就是让运维去改一个没变的配置。
type KeyKind uint8

const (
	// KindNodeIdentity 是 tailcat 服务端身份（决定地址，由对端的 vpn.peers[].address 携带）。
	KindNodeIdentity KeyKind = 1 << iota
	// KindClientKey 是访问侧 client 私钥（决定 nodekey，由对端的 vpn.allow_clients 匹配）。
	KindClientKey
)

// 每一半身份在对端的**收件人字段**：提示与"旧的还在谁手里"两处都必须用它。
//
// 取值是配置里真实存在的 JSON 字段名（英文），不做翻译——运维要拿它去配置文件里搜索，
// 而"翻译过的字段名"是搜不到的。
const (
	// RecipientNodeKey 是 client nodekey 要填到对端的字段。
	RecipientNodeKey = "vpn.allow_clients"
	// RecipientAddress 是节点地址要填到对端的字段。
	RecipientAddress = "vpn.peers[].address"
)

// 下面几个函数返回的都是**直接打到终端给运维看的提示**，因此用中文（本项目的 CLI 文案
// 一律中文，见 cmd/easyss 的用法文本）；其中的配置字段名、命令名、flag 名保持原文。
// 包内其余字符串（错误、日志）仍是英文：它们面向排障与日志搜索，且已被测试与文档引用。

// PeerUpdateHint 返回"该去对端的哪个字段更新"那句话（一行，已含 注意： 前缀）。
//
// 换掉的那一半决定了要改哪个字段，因此它只提那一个字段；两个都换时地址与 nodekey 各自
// 携带对方没有的东西，缺一不可。
func PeerUpdateHint(replaced KeyKind) string {
	switch replaced {
	case KindClientKey:
		return "注意：对端必须更新为上面的新 client nodekey——对端的 " + RecipientNodeKey + " 按它匹配"
	case KindNodeIdentity:
		return "注意：对端必须更新为上面的新节点地址——对端的 " + RecipientAddress + " 携带它"
	default:
		return "注意：对端必须更新为上面的新值——" + RecipientAddress + " 携带地址，" +
			RecipientNodeKey + " 匹配 nodekey"
	}
}

// ConsequenceHint 返回"不改会怎样"这句话的两行说明（不含缩进，由调用方排版）。
//
// 只说**真的被换掉**的那一半的后果：只换 client key 时地址逐字节没变，说"旧地址带着上一个
// preshared key"就是一句与本次操作无关的话，而提示里出现无关的话会让整条提示被当成模板跳过。
//
// 两行而不是一行：第一句是结论，第二句是"还能怎么办"（去改对端配置，或在本机回滚）。这两件事
// 性质不同，挤成一行会让人读成一句长条件状语。replaced 为 0（什么都没换）时返回空串。
func ConsequenceHint(replaced KeyKind) []string {
	switch replaced {
	case KindClientKey | KindNodeIdentity:
		return []string{
			"旧地址里带着上一个 preshared key，旧 nodekey 也仍是对端 " + RecipientNodeKey + " 的匹配对象，",
			"因此没有跟着更新的对端连不上本节点；请更新每个对端，或使用下面「旧身份」里的值回滚",
		}
	case KindClientKey:
		return []string{
			"旧 nodekey 仍是对端 " + RecipientNodeKey + " 的匹配对象，因此没有跟着更新的对端无法向本节点建立流；",
			"请更新每个对端的 " + RecipientNodeKey + "，或使用下面「旧身份」里的值回滚",
		}
	case KindNodeIdentity:
		return []string{
			"旧地址里带着上一个 preshared key，因此没有跟着更新的对端连不上本节点；",
			"请更新每个对端的 " + RecipientAddress + "，或使用下面「旧身份」里的值回滚",
		}
	default:
		return nil
	}
}

// RegenerateFile 重新生成 path 指向的身份文件，并返回被替换掉的旧内容的备份路径。
//
// 语义与 LoadOrCreate 刻意相反：这里是**由人显式触发**的覆盖，因为换掉身份会让
// 所有对端的配置失效（地址内嵌 preshared key，client key 是对端白名单的匹配对象），
// 而 LoadOrCreate 的前提正是"绝不静默覆盖"。两条路径共用同一份原子写入。
//
// path 不存在时不是错误：那是一个还没有身份的新节点，直接生成即可（返回的备份路径
// 为空）。只有真替换了文件才产生备份，因此"这个节点被重新生成过"可以从备份文件的
// 存在看出来。
//
// 顺序是先备份、后写入：反过来的话，写入成功而备份失败会丢掉旧身份——而旧身份
// 恰恰是回滚的唯一凭据。备份本身也是原子覆盖（见 backupFile），因此"用本次的旧身份
// 覆盖上一次的备份"不会留下写到一半、新旧都不可用的中间态。
func RegenerateFile(path, what string, create func() ([]byte, error)) (string, error) {
	content, err := create()
	if err != nil {
		return "", fmt.Errorf("vpn: generate %s: %w", what, err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("vpn: create state dir %s: %w", dir, err)
		}
	}

	backup := ""
	switch _, err := os.Stat(path); {
	case err == nil:
		backup, err = backupFile(path)
		if err != nil {
			return "", err
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", fmt.Errorf("vpn: stat %s: %w", path, err)
	}

	if err := writeFileAtomic(path, content); err != nil {
		return backup, err
	}
	return backup, nil
}

// backupFile 把 path 的当前内容复制成 <path>.bak（覆盖上一次的备份）并返回备份路径。
//
// 复制而不是重命名：重命名会把文件从 path 上移走，于是"备份成功但写入失败"之后就
// 再也没有可用的身份了。权限位显式写 0600，不依赖源文件的权限位——备份最常见的
// 用途正是"从别处拷回来一份"，而那份文件的权限无从假设。
//
// 覆盖已有备份走同一套"先写临时文件再 rename"：直接截断重写的话，写到一半失败会同时
// 失去旧备份与被它覆盖的那份备份，而此时本机上已经没有任何一份可回滚的身份了。
func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vpn: read %s for backup: %w", path, err)
	}
	backup := path + BackupSuffix
	if err := writeFileAtomic(backup, data); err != nil {
		return "", err
	}
	return backup, nil
}

// writeFileAtomic 先写临时文件再 rename，使任何中途失败都不会在目标路径上留下
// 一个"看起来存在但内容不全"的密钥文件。
func writeFileAtomic(path string, content []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return fmt.Errorf("vpn: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vpn: rename %s: %w", tmp, err)
	}
	return nil
}
