package vpn

import (
	"net/http"
	"os"
	"strconv"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/config"
)

// derpSendQueueDepthEnv 是钉住的 tailscale 读取"内嵌中继每客户端待发队列深度"的
// 进程级开关名（见 derp/derpserver/derpserver.go 的 getPerClientSendQueueDepth：
// 它只在 derpserver.New 里被读一次，没有对应的构造参数或 setter）。
//
// 它**不是**一个受支持的配置面，只是本包把 server.vpn.derp_send_queue_depth 交给
// 那个 fork 的唯一通路：构造前临时写入、构造后立刻还原（见 applySendQueueDepth）。
// 运维不需要、也不应该设置它——进程环境里预先存在的同名值既不会生效，也不会被解释成
// 一个旋钮；配置项是唯一来源。fork 补上构造参数之后这里应当换成 API 调用并删掉常量。
const derpSendQueueDepthEnv = "TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH"

// newDERPServer 是构造内嵌中继的注入点：生产路径就是 derpserver.New，测试替换它
// 以证明"队列深度在构造那一刻确实在进程环境里"（构造参数在 fork 里不存在）。
var newDERPServer = derpserver.New

// DERPServer 是本进程内嵌的 DERP 中继。
//
// 它只做中继：客户端与对端各自与自己 tailcat 服务端之间建立 WireGuard 会话，
// 打洞失败时数据经这里转发。因为中继与代理服务端在同一个进程/同一个 HTTPS 监听上，
// 节点之间"打不通就走服务端"不需要任何额外部署。
//
// 刻意不启用 client 校验（SetVerifyClient 默认为 false，且我们不会去改它）：
// 那套校验依赖本机运行 tailscaled 的 LocalAPI，与"不依赖 Tailscale 官方组件"
// 的目标冲突。接入控制由 tailcat 地址里的 preshared key 与可选的对端面白名单
// （vpn.allow_clients）负责。
type DERPServer struct {
	srv     *derpserver.Server
	handler http.Handler

	// sendQueueDepth 是实际落位的每客户端待发队列深度（已归一化）。存下来是为了
	// 让启动日志与测试能引用的就是"生效值"，而不是再算一次配置。
	sendQueueDepth int
}

// NewDERPServer 用持久化的 DERP 私钥构造内嵌 DERP 服务端。
//
// sendQueueDepth 是每个已连接客户端的待发帧队列深度：0（或负值）取
// config.DefaultDERPSendQueueDepth，越界钳制到
// [config.MinDERPSendQueueDepth, config.MaxDERPSendQueueDepth]（归一化
// 只在 config.NormalizeDERPSendQueueDepth 里定义一次）。它是这条中继路径上
// 唯一能存住未确认数据的地方，因此直接决定单条 TCP 流能有多少在途数据：吞吐 ≈
// 深度 × 每帧约 1.4KB / 端到端 RTT。
//
// 落位方式是"构造前临时写入、构造后立刻还原"（见 applySendQueueDepth）：fork 只在
// derpserver.New 里读一次那个进程级开关，且没有构造参数。因此**配置项是唯一旋钮**，
// 进程环境里预先存在的同名值既不生效、也不会被当成受支持的入口。
//
// 私钥必须持久化：DERP 公钥会写在握手响应里（Derp-Public-Key），换钥匙会让
// 已在线的节点需要重连，也让排障时的日志对不上。
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

// applySendQueueDepth 把队列深度暂时交给钉住的 tailscale，返回还原函数。
//
// 之所以要还原而不是留着：那个名字是 tailscale 的调试开关，留着会让"进程环境里有
// 一个值"看起来像一个受支持的配置入口；而队列深度在 derpserver.New 里就被抄进了
// 它自己的字段（此后的客户端环形缓冲都按那个字段分配），所以还原不影响已经建好的
// 中继，也不影响此后新建的客户端。写入失败时退回它的默认值（32 帧）仍然是一个能
// 工作的中继，因此只记日志，不让服务端起不来。
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

// Handler 返回应挂在 config.DefaultVPNDERPPath 下的处理器。
func (d *DERPServer) Handler() http.Handler {
	return d.handler
}

// PublicKey 返回 DERP 中继的公钥（排障与日志用）。
func (d *DERPServer) PublicKey() key.NodePublic {
	return d.srv.PublicKey()
}

// SendQueueDepth 返回实际生效的每客户端待发队列深度（已归一化）。
func (d *DERPServer) SendQueueDepth() int {
	return d.sendQueueDepth
}

// Close 关闭中继并断开所有已连接的客户端。
func (d *DERPServer) Close() error {
	if d == nil || d.srv == nil {
		return nil
	}
	return d.srv.Close()
}
