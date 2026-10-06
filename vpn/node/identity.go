package vpnnode

import (
	"encoding/json"
	"fmt"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/vpn"
)

// NodeIdentity 是 tailcat 服务端的长期身份。
//
// 它直接复用 tailcat.PrivateKey（node 私钥 + 含 preshared key / disco 公钥的
// ConnInfo），因为 **disco 公钥无法从 node 私钥推导**：tailcat 用的是内部函数
// discoPrivateForNode，没有导出 API。tailcat 自己的 `genkey`/`serve` 也正是把
// 这个结构整体以 JSON 落盘并读回，所以复用它的格式既是唯一可行的做法，也让
// 上游的调试工具能直接读我们的密钥文件。
//
// 三个字段缺一不可：Private 决定地址里的公钥，PresharedKey 是地址里携带的秘密
// （WireGuard 握手会混入它），ServerDiscoPublic 是客户端建立路径发现所需的
// 公钥。任何一个丢失或变化，都会产生一个所有对端都需要重新配置的新地址。
type NodeIdentity struct {
	tailcat.PrivateKey
}

// Address 返回本节点在给定 region 下的 tailcat 地址。
//
// region 由调用方给出（见 vpn.BuildRegion）：地址必须内嵌 DERP 详情才是完整展开
// 格式，客户端拿到它就不需要查询任何 DERPMap。
func (ni *NodeIdentity) Address(region *tailcfg.DERPRegion) string {
	ci := ni.Public
	ci.Region = []*tailcfg.DERPRegion{region}
	return string(ci.Addr())
}

// NodeKeyString 返回本 node 私钥对应的公钥文本（"nodekey:<hex>"），即
// `vpn.allow_clients` 里要填的那串东西。启动日志用它，使运维不必去猜白名单格式。
func NodeKeyString(k key.NodePrivate) string {
	return k.Public().String()
}

// LoadOrCreateNodeIdentity 读取或生成 tailcat 服务端身份。
func LoadOrCreateNodeIdentity(path string) (*NodeIdentity, error) {
	var ni NodeIdentity

	err := vpn.LoadOrCreate(path, "node identity",
		func() ([]byte, error) {
			return json.MarshalIndent(NodeIdentity{PrivateKey: *tailcat.NewPrivateKey()}, "", "  ")
		},
		func(data []byte) error { return json.Unmarshal(data, &ni) },
	)
	if err != nil {
		return nil, err
	}

	// 手改过或来自旧版本的文件可能缺字段。这些字段缺失时 tailcat 会在启动或首次
	// 访问对端时才失败，而且错误信息不会指向密钥文件，因此在这里提前拦。
	if ni.Private.IsZero() {
		return nil, fmt.Errorf("vpn: %s: node private key is missing (delete the file to regenerate, but every peer will need the new address)", path)
	}
	if ni.Public.ServerPublic.IsZero() {
		return nil, fmt.Errorf("vpn: %s: server public key is missing (delete the file to regenerate, but every peer will need the new address)", path)
	}
	if ni.Public.ServerDiscoPublic.IsZero() {
		return nil, fmt.Errorf("vpn: %s: disco public key is missing (delete the file to regenerate, but every peer will need the new address)", path)
	}
	if ni.Public.PresharedKey.IsZero() {
		return nil, fmt.Errorf("vpn: %s: preshared key is missing (delete the file to regenerate, but every peer will need the new address)", path)
	}
	return &ni, nil
}
