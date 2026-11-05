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

// newDERPDialer 返回交给 tailcat 的 DERP 拨号器（DERPDialer 选项）：tailcat 到内嵌 DERP 的
// TCP 连接由此经 easyss 隧道送出。不能改用 ALL_PROXY（tailcat 在 createEngine 里调用
// netns.SetEnabled(false)），也不能用无缓冲的 net.Pipe（实测与缓冲取值见 docs/architecture.md 要点 19）。
func newDERPDialer(handler *proxy.StreamHandler, method protocol.Method) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(network, "tcp") {
			return nil, fmt.Errorf("vpn: the DERP relay is reached over TCP, not %q", network)
		}

		// 拨号上下文由 DERP 客户端在返回后立刻取消（derphttp 的 dialNode 里 defer cancel），
		// 而这条流的寿命是整个 DERP 连接，因此必须剥掉取消；收尾交给管道关闭。
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
