package vpnnode

import (
	"encoding/json"
	"errors"
	"fmt"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/vpn"
)

// NodeIdentity 是 tailcat 服务端的长期身份，直接复用 tailcat.PrivateKey 的落盘格式
// （tailcat 自己的 genkey/serve 也读写它）。disco 公钥无法从 node 私钥推导，因此
// Private/PresharedKey/ServerDiscoPublic 缺一不可：丢失或变化都会让所有对端需要重配。
type NodeIdentity struct {
	tailcat.PrivateKey
}

// Address 返回本节点在给定 region 下的 tailcat 地址；地址必须内嵌 DERP 详情
// （完整展开格式），客户端拿到它就不需要查询任何 DERPMap。
func (ni *NodeIdentity) Address(region *tailcfg.DERPRegion) string {
	ci := ni.Public
	ci.Region = []*tailcfg.DERPRegion{region}
	return string(ci.Addr())
}

// NodeKeyString 返回 "nodekey:<hex>"，即 vpn.allow_clients 里要填的值。
func NodeKeyString(k key.NodePrivate) string {
	return k.Public().String()
}

// NewNodeIdentity 生成一个全新的内存身份，不落盘（落盘见 RegenerateNodeIdentityFile）。
func NewNodeIdentity() *NodeIdentity {
	return &NodeIdentity{PrivateKey: *tailcat.NewPrivateKey()}
}

// marshalNodeIdentity 是身份文件的落盘内容。
func marshalNodeIdentity(ni *NodeIdentity) ([]byte, error) {
	return json.MarshalIndent(ni, "", "  ")
}

// parseNodeIdentity 解析并校验一份身份文件的内容。校验放在这里，是因为 regen 必须
// 在落盘**之前**确认写出的内容可用。错误只描述哪里不对：路径与修法提示由调用方补，
// 自己再加一遍会拼出两份。
func parseNodeIdentity(data []byte) (*NodeIdentity, error) {
	var ni NodeIdentity
	if err := json.Unmarshal(data, &ni); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	// 缺字段时 tailcat 要到启动或首次访问对端才失败，且错误信息不指向密钥文件，
	// 因此在这里提前拦。
	if ni.Private.IsZero() {
		return nil, errors.New("node private key is missing")
	}
	if ni.Public.ServerPublic.IsZero() {
		return nil, errors.New("server public key is missing")
	}
	if ni.Public.ServerDiscoPublic.IsZero() {
		return nil, errors.New("disco public key is missing")
	}
	if ni.Public.PresharedKey.IsZero() {
		return nil, errors.New("preshared key is missing")
	}
	return &ni, nil
}

// LoadOrCreateNodeIdentity 读取或生成 tailcat 服务端身份。
func LoadOrCreateNodeIdentity(path string) (*NodeIdentity, error) {
	var ni *NodeIdentity

	err := vpn.LoadOrCreate(path, "node identity",
		func() ([]byte, error) { return marshalNodeIdentity(NewNodeIdentity()) },
		// 错误由 vpn.LoadOrCreate 补上路径与"该跑哪条命令"，两个入口拿到的是同一个。
		func(data []byte) error {
			parsed, err := parseNodeIdentity(data)
			if err != nil {
				return err
			}
			ni = parsed
			return nil
		})
	if err != nil {
		return nil, err
	}
	return ni, nil
}

// LoadOrCreateNodeIdentityFile 与 LoadOrCreateNodeIdentity 返回同样的两个值。
// 文件损坏或字段缺失时是 (nil, err)，**没有任何错误之外的副作用**（不生成、不覆盖），
// 因此只读命令可以把它当成一种可显示的结果。
func LoadOrCreateNodeIdentityFile(path string) (*NodeIdentity, error) {
	return LoadOrCreateNodeIdentity(path)
}

// RegenerateNodeIdentityFile 把 ni 落盘成身份文件，返回被替换的旧内容的备份路径
// （path 不存在时为空）。接收生成好的身份是调用方的顺序要求：新地址必须先推导成功。
// 落盘前后各校验一次；落盘后读回，因为磁盘满或临时文件被截断只有读回才知道。
func RegenerateNodeIdentityFile(path string, ni *NodeIdentity) (string, error) {
	content, err := marshalNodeIdentity(ni)
	if err != nil {
		return "", fmt.Errorf("vpn: generate node identity: %w", err)
	}
	if _, err := parseNodeIdentity(content); err != nil {
		return "", fmt.Errorf("vpn: %s: %w; refusing to write it", path, err)
	}
	backup, err := vpn.RegenerateFile(path, "node identity", func() ([]byte, error) { return content, nil })
	if err != nil {
		return backup, err
	}
	if _, err := LoadOrCreateNodeIdentity(path); err != nil {
		return backup, fmt.Errorf("the regenerated node identity is not usable: %w", err)
	}
	return backup, nil
}
