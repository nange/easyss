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
//     的配置都要跟着改，必须由人决定）；
//   - 文件不存在 → 用 create 生成内容、以 0600 原子写入；
//   - 其他读取错误（权限等）→ 原样报错，不要伪装成"文件不存在"。
func LoadOrCreate(path, what string, create func() ([]byte, error), load func([]byte) error) error {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := load(data); err != nil {
			return fmt.Errorf("vpn: %s: corrupt %s: %w (delete the file to regenerate, but every peer will need the new address)", path, what, err)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return fmt.Errorf("vpn: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vpn: rename %s: %w", tmp, err)
	}
	// 新建之后必须把内容读回调用方：两条路径（读既有文件 / 刚生成）返回的身份
	// 必须来自同一份字节，否则"新建时拿到零值"这类错误只会在首次启动时出现。
	return load(content)
}
