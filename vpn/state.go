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

// StateDirName 是相对可执行文件目录的 VPN 状态目录名；身份密钥与对端面地址都在这里，备份/
// 迁移一个节点只需带走它。本文件只依赖 tailscale.com/types/key，绝不能引入 tailcat（那会把
// WireGuard 引擎拖进只跑 DERP 中继的服务端，见 deps_test.go）。
const StateDirName = "vpn"

// StateDir 用可执行文件目录而不是 XDG 配置目录：config.json 与日志本来就在二进制旁
// （macOS .app bundle 由 util.CurrentDir 处理），密钥放在同一处才不会与配置错位。
func StateDir() string {
	return filepath.Join(util.CurrentDir(), StateDirName)
}

func NodeIdentityPath() string { return filepath.Join(StateDir(), "node-identity.json") }

// ClientKeyPath 返回的私钥必须跨重启稳定：vpn.allow_clients 按 node key 匹配，换 key 白名单
// 立刻失效。
func ClientKeyPath() string { return filepath.Join(StateDir(), "client.key") }

func DERPKeyPath() string { return filepath.Join(StateDir(), "derp.key") }

// NodeKeyString 返回 vpn.allow_clients 要填的 "nodekey:<hex>" 文本。
func NodeKeyString(k key.NodePrivate) string {
	return k.Public().String()
}

// LoadOrCreateKey 读取 path 中的 node 私钥，不存在则生成并原子落盘（文件 0600、目录 0700）：
// 访问侧 client key 与 DERP 私钥共用它，两者都必须跨重启稳定；截断的文件会被当成损坏，而
// 损坏的代价是所有对端都要重新配置。
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

// LoadKey 只读取 path 中的 node 私钥，不生成：不存在时返回 fs.ErrNotExist，损坏时报错。
// 需要"读密钥但不产生副作用"的路径（--dry-run）用它，而不是 LoadOrCreateKey。
func LoadKey(path string) (key.NodePrivate, error) {
	var k key.NodePrivate
	if err := Load(path, "node key", func(data []byte) error { return k.UnmarshalText(bytes.TrimSpace(data)) }); err != nil {
		return key.NodePrivate{}, err
	}
	return k, nil
}

// Load 只读取并解析 path，不生成：文件不存在时返回满足 errors.Is(err, fs.ErrNotExist) 的错误，
// 由调用方决定是否补建（见 LoadOrCreate）；损坏必须报错，那也是"绝不能静默覆盖"的一半。
func Load(path, what string, load func([]byte) error) error {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := load(data); err != nil {
			return fmt.Errorf("vpn: %s: corrupt %s: %w (%s, but every peer will need the new address)", path, what, err, RegenHint)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return err
	default:
		return fmt.Errorf("vpn: read %s: %w", path, err)
	}
}

// LoadOrCreate 读不到就生成，但绝不静默覆盖：文件存在却无法解析必须报错（覆盖等于换掉身份）；
// 其它读取错误原样返回，不能伪装成"文件不存在"。新文件以 0600 原子写入。
func LoadOrCreate(path, what string, create func() ([]byte, error), load func([]byte) error) error {
	if err := Load(path, what, load); !errors.Is(err, fs.ErrNotExist) {
		return err
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
	if err := writeFileAtomic(path, content); err != nil {
		return err
	}
	// 新建之后必须把内容读回调用方：两条路径返回的身份必须来自同一份字节。
	return load(content)
}

// BackupSuffix 是 RegenerateFile 的备份后缀：每个身份文件只留一份固定名备份，它就是上一次
// 生效的身份（回滚点与新旧对照物），每次重新生成都会覆盖它。
const BackupSuffix = ".bak"

// IdentityRegenPending 报告当前身份与备份不同（曾被重新生成，旧身份可能仍在某些对端手里）。
// 判据必须是内容而不是 mtime：备份与身份文件在同一次操作里先后写入，且拷回备份后 mtime 可能
// 反向。任何读取失败（含没有备份）都返回 false——一条提示不值得让命令失败。
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

// RegenHint 是身份文件损坏或需要轮换时该跑的命令。调用方（runner）要把读不出来的身份变成
// 地址那半的失败原因，因此它必须导出；错误文案内联同一句话是为了能独立读懂。
const RegenHint = "run \"easyss vpn regen\" to regenerate it"

// KeyKind 指定重写哪一半身份，位掩码便于组合（两个都换 = 相或）。定义在身份包里是为了让提示
// 文案与旧值回显共用同一份判断：只换一半时提到另一个字段会让运维去改没变的配置。
type KeyKind uint8

const (
	// KindNodeIdentity 是 tailcat 服务端身份，决定地址（由对端的 vpn.peers[].address 携带）。
	KindNodeIdentity KeyKind = 1 << iota
	// KindClientKey 是访问侧 client 私钥，决定 nodekey（由对端的 vpn.allow_clients 匹配）。
	KindClientKey
)

// 每一半身份在对端的收件人字段：取值是配置文件里真实存在的 JSON 字段名，不做翻译——运维要
// 拿它去配置文件里搜索。
const (
	// RecipientNodeKey 是 client nodekey 要填到对端的字段。
	RecipientNodeKey = "vpn.allow_clients"
	// RecipientAddress 是节点地址要填到对端的字段。
	RecipientAddress = "vpn.peers[].address"
)

// 下面几个函数返回直接打到终端给运维看的提示，因此用中文；配置字段名、命令名、flag 名保持
// 原文。包内其余字符串（错误、日志）仍是英文：面向排障与日志搜索，且已被测试与文档引用。

// PeerUpdateHint 返回"该去对端的哪个字段更新"一行（含 注意： 前缀），只提被换掉的那一半；
// 两半都换时两个字段都不可省。
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

// ConsequenceHint 返回"不改会怎样"的两行说明（不含缩进，由调用方排版），只覆盖真正换掉的
// 那一半；replaced 为 0（什么都没换）时返回 nil。
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

// RegenerateFile 由人显式触发身份覆盖，语义与 LoadOrCreate 相反：换身份会让所有对端的配置
// 失效。必须先备份、后写入（反过来写入成功而备份失败就丢掉唯一的回滚凭据）；path 不存在时
// 直接生成、不产生备份。
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

// backupFile 把当前内容复制成 <path>.bak（覆盖上一份）：用复制而不是重命名，否则"备份成功
// 但写入失败"后 path 上再没有可用身份；覆盖也走临时文件 + rename，中途失败不会同时丢掉新旧
// 两份备份。权限位固定 0600，不信任来源文件。
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

// writeFileAtomic 先写临时文件再 rename，失败不会在目标路径留下残缺文件。
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
