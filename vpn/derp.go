package vpn

import (
	"net/http"
	"os"
	"strconv"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/config"
)

// 钉住的 tailscale 开关名：derpserver.New 只在构造时读一次，没有构造参数。它是
// server.vpn.derp_send_queue_depth 唯一的落位通路（构造前写入、构造后还原），不是
// 配置面；进程环境里预先存在的同名值既不生效也不被改动。
const derpSendQueueDepthEnv = "TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH"

// newDERPServer 是构造内嵌中继的注入点：生产路径就是 derpserver.New，测试替换它来观察
// 构造那一刻的进程环境。
var newDERPServer = derpserver.New

// DERPServer 是进程内的 DERP 中继：打洞失败时节点数据经它转发，与代理服务端共用同一个
// HTTPS 监听。刻意不启用上游的 client 校验（它依赖本机 tailscaled 的 LocalAPI），接入
// 控制由 tailcat 地址里的 preshared key 与 vpn.allow_clients 承担。
type DERPServer struct {
	srv     *derpserver.Server
	handler http.Handler

	// sendQueueDepth 是归一化后实际生效的队列深度（启动日志与测试引用它）。
	sendQueueDepth int
}

// NewDERPServer 用持久化的 DERP 私钥构造内嵌中继：深度归一化后经进程级开关在
// derpserver.New 之前落位（见 applySendQueueDepth）。私钥必须跨重启稳定：公钥写在握手
// 响应里，换钥匙会让在线节点重连、日志对不上；吞吐模型见 docs/architecture.md 要点 19。
func NewDERPServer(privateKey key.NodePrivate, sendQueueDepth int) *DERPServer {
	depth := config.NormalizeDERPSendQueueDepth(sendQueueDepth)

	restore := applySendQueueDepth(depth)
	srv := newDERPServer(privateKey, Logf)
	restore()

	return &DERPServer{
		srv:            srv,
		handler:        derpserver.Handler(srv),
		sendQueueDepth: depth,
	}
}

// applySendQueueDepth 在 derpserver.New 之前临时写入队列深度，返回还原函数。深度在 New
// 里就被抄进上游字段，还原不影响已建或新建的客户端；写入失败退回上游默认值（32 帧），
// 只记日志、不让服务端起不来。
func applySendQueueDepth(depth int) func() {
	prev, had := os.LookupEnv(derpSendQueueDepthEnv)
	if err := os.Setenv(derpSendQueueDepthEnv, strconv.Itoa(depth)); err != nil {
		Logf("vpn: cannot apply derp send queue depth %d (%v); keeping derpserver's own default", depth, err)
		return func() {}
	}
	return func() {
		if had {
			_ = os.Setenv(derpSendQueueDepthEnv, prev)
			return
		}
		_ = os.Unsetenv(derpSendQueueDepthEnv)
	}
}

// Handler 必须挂在 config.DefaultVPNDERPPath 下（DERP 客户端按该路径握手）。
func (d *DERPServer) Handler() http.Handler {
	return d.handler
}

func (d *DERPServer) PublicKey() key.NodePublic {
	return d.srv.PublicKey()
}

func (d *DERPServer) SendQueueDepth() int {
	return d.sendQueueDepth
}

// Close 幂等且 nil 安全：服务端 Shutdown 与会话切换可能各调一次。
func (d *DERPServer) Close() error {
	if d == nil || d.srv == nil {
		return nil
	}
	return d.srv.Close()
}
