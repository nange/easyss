package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/netpipe"
)

// newDERPDialer 返回交给 tailcat 的 DERP 拨号器（见 tailcat.Server/Client 的
// DERPDialer 选项）：tailcat 到内嵌 DERP 的 TCP 连接由此经 easyss 隧道送出。
//
// 为什么必须是拨号器，而不是环境变量：
//
//   - tailcat 在 createEngine 里调用 netns.SetEnabled(false)，因此 netns.NewDialer
//     返回的是**未包装**的普通拨号器，ALL_PROXY 那条路在 tailcat 里根本不会生效；
//   - 拨号器还顺带解决了平台差异（netns 的 SOCKS 包装在 android/ios/js 构建里被
//     排除）与"进程级开关只读一次"这两件事。
//
// 实现上把中继式的 StreamHandler.OpenTCPStream 适配成"返回一条连接"：netpipe 的
// 两端，一端交给 handler 搬运，另一端返回给 tailcat。这样复用的是**生产路径上
// 已经在跑的那段中继**（引导记录、整形、空闲超时、槽位排空、半关闭都由它处理），
// 而不是另写一份读写循环；netpipe 自带 deadline 语义，DERP 客户端对连接设置的
// 超时因此照常生效。
//
// 为什么不是 net.Pipe：net.Pipe 没有缓冲，于是"DERP 客户端写一个包"必须等中继
// goroutine 读走，而中继 goroutine 会在隧道写阻塞时停住——背压直接打在 magicsock
// 那个 32 深、满了丢最旧的 DERP 写队列上，内层 TCP 的拥塞窗口随之崩掉。tailscale
// 的设计假设是"DERP 连接是真实 TCP 套接字、有几 MB 内核缓冲"，net.Pipe 把这个前提
// 抽掉了。实测（单程 60ms、内层 RTT 240ms、中继队列 1024 帧）：普通 TCP 套接字
// 2929 KB/s，无缓冲 net.Pipe 175 KB/s。netpipe 用共享配置里的固定缓冲换回这一项。
func newDERPDialer(handler *proxy.StreamHandler, method protocol.Method) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("vpn: the DERP relay is reached over TCP, not %q", network)
		}

		// 拨号上下文由 DERP 客户端在拨号返回后立刻取消（derphttp 在 dialNode
		// 里 defer cancel），而这条流的寿命是整个 DERP 连接，因此这里必须剥掉
		// 取消：流的收尾交给管道关闭（tailcat 关闭连接 → 中继退出 → 流关闭）。
		streamCtx := context.WithoutCancel(ctx)

		local, remote := netpipe.Pipe(config.DERPPipeBufferSize)
		go func() {
			err := handler.OpenTCPStream(streamCtx, addr, method, remote)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warn("[VPN] derp stream", "target", addr, "err", err)
			}
			_ = remote.Close()
		}()
		return local, nil
	}
}
