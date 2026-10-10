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

// NewNodeIdentity 生成一个全新的 tailcat 服务端身份。
//
// 调用方拿到的是**内存里的值**，落盘由 RegenerateNodeIdentityFile 负责：重新生成要先
// 推导（新身份的地址能不能算出来、是不是完整展开格式），只有推导通过才该写文件。
func NewNodeIdentity() *NodeIdentity {
	return &NodeIdentity{PrivateKey: *tailcat.NewPrivateKey()}
}

// marshalNodeIdentity 是身份文件的落盘内容（见 NodeIdentity 对格式来源的说明）。
func marshalNodeIdentity(ni *NodeIdentity) ([]byte, error) {
	return json.MarshalIndent(ni, "", "  ")
}

// parseNodeIdentity 解析并校验一份身份文件的内容。
//
// 校验集中在这里而不是 LoadOrCreateNodeIdentity 里，是因为"重新生成"路径必须在
// **落盘之前**确认自己写出的东西是可用的：一个刚生成却缺字段的身份文件比没有文件
// 更难排查。
//
// 错误信息只描述"哪里不对"，不带路径与修法：两个调用方各自补上那两句——vpn.LoadOrCreate
// 会加 "vpn: <path>: ... (run \"easyss vpn regen\" ...)"，RegenerateNodeIdentityFile 在
// 落盘前的自查里补上路径。自己再加一遍会拼出两份路径与两份提示。
func parseNodeIdentity(data []byte) (*NodeIdentity, error) {
	var ni NodeIdentity
	if err := json.Unmarshal(data, &ni); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	// 手改过或来自旧版本的文件可能缺字段。这些字段缺失时 tailcat 会在启动或首次
	// 访问对端时才失败，而且错误信息不会指向密钥文件，因此在这里提前拦。
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
		// 这里的错误会被 vpn.LoadOrCreate 补上路径与"该跑哪条命令"；只读路径
		//（LoadOrCreateNodeIdentityFile）拿到的是同一个错误，因此上层能原样展示。
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

// LoadOrCreateNodeIdentityFile 与 LoadOrCreateNodeIdentity 返回同样的两个值，区别只在
// 调用方怎么用：文件损坏或字段缺失时它是 (nil, err)，**没有任何错误之外的副作用**
// （不会生成、不会覆盖），因此"只读"命令可以把它当成一种可显示的结果。
//
// `easyss vpn identity` 正是这么用的：身份文件坏掉不该让整条命令失败——client
// nodekey 仍然要打印出来（它根本不依赖这个文件），而地址那半正好用这个 nil 说明
// "为什么算不出来"。
func LoadOrCreateNodeIdentityFile(path string) (*NodeIdentity, error) {
	return LoadOrCreateNodeIdentity(path)
}

// RegenerateNodeIdentityFile 把 ni 落盘成身份文件，返回被替换掉的旧内容的备份路径。
//
// 接收已经生成好的身份（而不是自己生成）是调用方的要求：新身份的地址必须先推导成功，
// 才能覆盖掉那个"旧地址仍然有效"的文件（见 runner.RegenerateVPNIdentity）。
//
// 落盘前后各校验一次：生成前用 marshalNodeIdentity 的字节自查一遍，是为了不把一份缺
// 字段的身份写进文件（它比没有文件更难排查——tailcat 会在启动或首次访问对端时才失败，
// 且错误信息不指向密钥文件）；落盘后读回，是因为"文件到底能不能被读回"只有读回才知道
// （磁盘满、临时文件被截断都属于这一类）。
//
// path 不存在时不产生备份（返回空路径）。
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
