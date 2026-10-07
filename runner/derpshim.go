package runner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
)

// allProxyEnv 是 tailscale 的 netns 拨号器读取的 SOCKS5 代理环境变量。
//
// 事实链（都在 go.mod 钉住的版本里）：derphttp 的 region 拨号走
// netns.NewDialer（derp/derphttp/derphttp_client.go 的 dialContext），netns 在
// 非 android/ios/js 的构建里用 golang.org/x/net/proxy 的
// FromEnvironmentUsing 包装它（net/netns/socks.go），而后者读 ALL_PROXY。
// 因此设置这个变量就等于"tailscale 自己的出站连接走 easyss"。
//
// 两个约束值得写下来：
//   - x/net/proxy 用 sync.Once 缓存这个值，进程内只读一次，所以必须在任何
//     tailcat 拨号之前设置（与 vpnnode.ApplyRelayOnly 同一类约束）；
//   - 它只影响走 netns 的拨号（本进程里就是 tailcat），Go 标准库的
//     http.DefaultTransport 不读 ALL_PROXY。
const allProxyEnv = "ALL_PROXY"

// derpShim 是 tailcat 通往内嵌 DERP 的唯一出口：一个只绑回环、把所有 CONNECT
// 都送进 easyss 隧道的 SOCKS5 服务。
//
// 为什么需要它，而不是让 tailcat 直连 DERP（见 docs/vpn-design.md 3.3）：
// 服务端的 /derp 只接受到来自回环的连接，节点侧的 DERP 连接必须经 easyss 协议
// 到达服务端，再由服务端映射回自己的回环监听。这样内嵌 DERP 不再是公网上的匿名
// 中继，也不再有任何可被扫描的 DERP 指纹。
//
// 它刻意不使用用户的 routePolicy：shim 的 Router 恒为"全部走代理"
// （router.NewProxyOnly），因此用户的 proxy_rule / GeoIP 判定都不可能把 DERP
// 连接变成直连——那会让 VPN 静默失效（DERP 私有化后直连是连不上的）。
//
// 它也不限制目标主机（不校验"只能连配置的 DERP 主机"）：入口只绑回环、且只服务本
// 进程里的 tailcat，而 tailcat 的目标来自这份配置本身；本机用户能借它到达的目标，
// 与主 SOCKS5 入口（同样只绑回环、同样由 master key 保护）完全一样。
type derpShim struct {
	srv  *proxy.Socks5Server
	addr string
	// proxyWasSet/prevAllProxy 记录本进程原有的 ALL_PROXY，供 close 还原。
	proxyWasSet  bool
	prevAllProxy string
}

// derpShimPort 返回 shim 的监听端口：对端面端口之后的第一个端口。
//
// 端口必须**确定性**，不能用 :0：ALL_PROXY 的值在进程内只被读取一次并缓存，
// 同一个进程里第二次 StartVPN 仍然用第一次的地址，随机端口会让第二次会话指向
// 一个已经关闭的端口。peer_port 只在 tailcat 的 gVisor netstack 里监听（宿主上
// 不占端口），因此它后面的第一个端口在宿主上是空的。
func derpShimPort(peerPort int) (int, error) {
	if peerPort <= 0 || peerPort > 65535 {
		return 0, fmt.Errorf("vpn.peer_port %d is not a valid port", peerPort)
	}
	if peerPort == 65535 {
		return 0, fmt.Errorf("vpn.peer_port %d leaves no room for the internal DERP entry port", peerPort)
	}
	return peerPort + 1, nil
}

// startDERPShim 绑定回环上的 shim 并把 ALL_PROXY 指向它。
//
// 它必须在任何 tailcat 组件启动之前调用：ALL_PROXY 是进程级、只读一次的
// （见 allProxyEnv），晚设等于没设。
func startDERPShim(handler *proxy.StreamHandler, method protocol.Method, timeouts sharedconfig.Timeouts, peerPort int) (*derpShim, error) {
	if !derpEnvProxySupported() {
		return nil, errors.New("this platform's tailscale build ignores " + allProxyEnv +
			" (the SOCKS dialer is excluded on android/ios/js), so the embedded DERP cannot be kept private")
	}
	port, err := derpShimPort(peerPort)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// 同步探测端口占用：Socks5Server.Start 会阻塞在 Serve 上，绑定错误只能在
	// 别处暴露，而这里必须让"端口被占"成为一个明确的启动错误（与 runner 对
	// 其它本地监听的处理一致）。
	if err := prebindTCP(addr); err != nil {
		return nil, fmt.Errorf("derp entry listen %s: %w", addr, err)
	}

	srv, err := proxy.NewSocks5Server(proxy.Socks5Options{
		ListenAddr: addr,
		Handler:    handler,
		// 恒为代理：DERP 连接必须走隧道，不能受用户分流规则影响。
		Router: router.NewProxyOnly(),
		Method: method,
		// 只承载 tailcat 的 TCP 连接：53 不是服务端口，UDP ASSOCIATE 也不需要。
		DisableDNSIntercept: true,
		DisableUDPAssociate: true,
		Timeouts:            timeouts,
	})
	if err != nil {
		return nil, fmt.Errorf("derp entry: %w", err)
	}

	shim := &derpShim{srv: srv, addr: addr}
	if prev, ok := os.LookupEnv(allProxyEnv); ok {
		shim.proxyWasSet = true
		shim.prevAllProxy = prev
		if prev != "socks5://"+addr {
			log.Warn("[VPN] overriding the existing "+allProxyEnv+" for this process: tailscale's DERP dials must go through easyss",
				"previous", prev, "now", "socks5://"+addr)
		}
	}
	if err := os.Setenv(allProxyEnv, "socks5://"+addr); err != nil {
		return nil, fmt.Errorf("set %s: %w", allProxyEnv, err)
	}

	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("[VPN] derp entry", "addr", addr, "err", err)
		}
	}()
	log.Info("[VPN] derp entry ready: tailscale's DERP dials are tunnelled through easyss",
		allProxyEnv, "socks5://"+addr)
	return shim, nil
}

// close 停止 shim 并还原进程原有的 ALL_PROXY。幂等，nil 安全。
//
// 还原只是环境卫生：x/net/proxy 已经把值缓存在进程里，因此它不会改变本进程
// 后续 dial 的行为（VPN 关闭时也没有 tailcat 组件会拨号）。
func (s *derpShim) close() {
	if s == nil {
		return
	}
	if s.srv != nil {
		_ = s.srv.Close()
	}
	if s.proxyWasSet {
		_ = os.Setenv(allProxyEnv, s.prevAllProxy)
	} else {
		_ = os.Unsetenv(allProxyEnv)
	}
}
