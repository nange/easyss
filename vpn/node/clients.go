package vpnnode

import (
	"errors"
	"fmt"
	"sync"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	vpn "github.com/nange/easyss/v3/vpn"
)

// errClientSetClosed 表示访问侧客户端集合已关闭：关闭之后不再建立新的隧道。
var errClientSetClosed = errors.New("vpn: client set is closed")

// ClientSetOptions 是构造访问侧客户端集合所需的输入。
type ClientSetOptions struct {
	// KeyPath 是访问侧 client 私钥的文件路径。Key 为零且 KeyPath 非空时，由
	// 本类型读取或生成它（见 vpn.LoadOrCreateKey）。
	KeyPath string
	// Key 是已加载的 client 私钥；为零时从 KeyPath 读取。
	Key key.NodePrivate
	// Peers 是本节点要访问的对端。地址在这里做一次 tailcat 解析自检：一个写错的
	// 地址不该等到第一次访问对端时才以网络错误的形式暴露，而且那时的错误信息里
	// 不会有"是哪个 peer"。
	Peers []PeerRef
	// DERPMapCache 是 tailcat 拉取 DERP map 时的缓存；nil 用它的进程内缓存。
	//
	// 正常情况下这个缓存**永远不会被访问**：peer 地址是完整展开格式（启动时由
	// AssertFullAddr 保证），`ConnInfo.Expand` 因此直接返回，不需要任何 DERP map
	// 来源。留这个出口是为了两件事：把缓存持久化（tailcat CLI 就是这么做的），
	// 以及让测试**证明**零访问——那等价于"零官方 DERPMap 请求"（见 4.7 与 12.5）。
	DERPMapCache tailcat.DERPMapCache
}

// ClientSet 按对端地址维护 tailcat 客户端，供访问侧拨号。
//
// 每个对端一个客户端：tailcat.Client 持有自己的 WireGuard 引擎与 netstack，且
// 一个 Client 只连一个 server 地址，因此"多对端"就是"多个 Client"。客户端是
// **懒创建**的——tailcat 的隧道在第一次拨号时才建立（Client.up），因此构造本类型
// 不会发起任何网络活动，也不会留下 goroutine；没用过的 Client 关闭是空操作。
//
// 整组共用一个 client 私钥：它必须在所有对端上一致，因为 `vpn.allow_clients`
// 白名单是按 node key 匹配的（见 docs/vpn-design.md 7.3）。
type ClientSet struct {
	key key.NodePrivate

	// derpMapCache 由调用方给出（见 ClientSetOptions.DERPMapCache），透传给每个
	// 客户端。
	derpMapCache tailcat.DERPMapCache

	mu      sync.Mutex
	clients map[string]*tailcat.Client
	closed  bool
}

// NewClientSet 构造访问侧客户端集合。它不建立任何隧道（见 ClientSet 的注释）。
func NewClientSet(opts ClientSetOptions) (*ClientSet, error) {
	k := opts.Key
	switch {
	case !k.IsZero():
	case opts.KeyPath != "":
		loaded, err := vpn.LoadOrCreateKey(opts.KeyPath)
		if err != nil {
			return nil, err
		}
		k = loaded
	default:
		return nil, errors.New("vpn: client set requires a client key or vpn.client_key_path")
	}

	for i, p := range opts.Peers {
		if _, err := tailcat.ParseAddr(tailcat.Addr(p.Address)); err != nil {
			return nil, fmt.Errorf("vpn: peers[%d] (%s): invalid tailcat address: %w", i, p.HostName, err)
		}
	}

	return &ClientSet{key: k, derpMapCache: opts.DERPMapCache, clients: make(map[string]*tailcat.Client)}, nil
}

// ClientKey 返回访问侧 client 公钥。启动日志把它打印成 nodekey:... 的形态，对端
// 的 `vpn.allow_clients` 里要填的就是这个值。
func (cs *ClientSet) ClientKey() key.NodePublic { return cs.key.Public() }

// clientFor 返回对端地址对应的客户端，必要时创建它。创建的客户端在第一次拨号时
// 才会真正建立隧道。
func (cs *ClientSet) clientFor(addr string) (*tailcat.Client, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed {
		return nil, errClientSetClosed
	}
	if c, ok := cs.clients[addr]; ok {
		return c, nil
	}

	c := tailcat.NewClient(tailcat.Addr(addr))
	// Key 必须显式设置：不设置时 tailcat 会在第一次使用时生成一把进程内临时 key，
	// 于是对端上的 allow_clients 白名单每次重启都失效，而失败表现只是"连不上"。
	c.Key = cs.key
	c.DERPMapCache = cs.derpMapCache
	// 把 tailcat 的 printf 风格日志接到本项目的日志器上，否则它会直接写标准库
	// log（在托盘应用里没有可读的输出位置）。
	c.Logf = vpn.Logf
	cs.clients[addr] = c
	return c, nil
}

// Close 关闭全部已创建的客户端并阻止后续拨号。幂等。
func (cs *ClientSet) Close() error {
	cs.mu.Lock()
	if cs.closed {
		cs.mu.Unlock()
		return nil
	}
	cs.closed = true
	clients := make([]*tailcat.Client, 0, len(cs.clients))
	for _, c := range cs.clients {
		clients = append(clients, c)
	}
	cs.clients = nil
	cs.mu.Unlock()

	// 在锁外关闭：Client.Close 会拆除 WireGuard 引擎与 DERP 连接，可能阻塞。
	var err error
	for _, c := range clients {
		if cerr := c.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
