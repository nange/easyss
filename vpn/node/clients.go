package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	vpn "github.com/nange/easyss/v3/vpn"
)

// errClientSetClosed 表示访问侧客户端集合已关闭：关闭之后不再建立新的隧道。
var errClientSetClosed = errors.New("vpn: client set is closed")

// ClientSetOptions 是构造访问侧客户端集合所需的输入。
type ClientSetOptions struct {
	// KeyPath 是访问侧 client 私钥的文件路径；Key 为零时由此读取或生成（见 vpn.LoadOrCreateKey）。
	KeyPath string
	// Key 是已加载的 client 私钥；为零时从 KeyPath 读取。
	Key key.NodePrivate
	// Peers 是本节点要访问的对端；构造时逐个做一次 tailcat 解析自检，使写错的地址
	// 在启动时就带着 peer 名字报错。
	Peers []PeerRef
	// DERPMapCache 是 tailcat 拉取 DERP map 时的缓存；nil 用它的进程内缓存。
	// 完整展开格式的地址让 ConnInfo.Expand 直接返回，正常路径下这个缓存不会被访问，
	// 测试即以此证明"零官方 DERPMap 请求"。
	DERPMapCache tailcat.DERPMapCache
	// DERPDialer / DERPOnly 交给每个 tailcat 客户端的同名选项（见
	// PeerFaceOptions）。
	DERPDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	DERPOnly   bool
}

// ClientSet 按对端地址维护 tailcat 客户端，供访问侧拨号。
// 每个对端一个 Client：它持有自己的 WireGuard 引擎与 netstack，只连一个 server 地址，
// 隧道在第一次拨号时才建立。整组共用一把 client 私钥，因为 allow_clients 按 node key 匹配。
type ClientSet struct {
	key key.NodePrivate

	// derpDialer/derpOnly 透传给每个客户端（见 ClientSetOptions）。
	derpDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	derpOnly   bool

	// derpMapCache 透传给每个客户端（见 ClientSetOptions.DERPMapCache）。
	derpMapCache tailcat.DERPMapCache

	mu      sync.Mutex
	clients map[string]*tailcat.Client
	closed  bool
}

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

	return &ClientSet{
		key:          k,
		derpMapCache: opts.DERPMapCache,
		derpDialer:   opts.DERPDialer,
		derpOnly:     opts.DERPOnly,
		clients:      make(map[string]*tailcat.Client),
	}, nil
}

// ClientKey 返回访问侧 client 公钥（形如 nodekey:<hex>），对端 vpn.allow_clients 填的就是它。
func (cs *ClientSet) ClientKey() key.NodePublic { return cs.key.Public() }

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
	// Key 必须显式设置：否则 tailcat 会在首次使用时生成进程内临时 key，对端
	// allow_clients 每次重启后失效，而失败表现只是"连不上"。
	c.Key = cs.key
	c.DERPMapCache = cs.derpMapCache
	c.DERPDialer = cs.derpDialer
	c.DERPOnly = cs.derpOnly
	// Logf 接本项目的日志器；不接时 tailcat 直接写标准库 log，托盘应用里看不到。
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
