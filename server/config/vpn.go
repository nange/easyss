package config

import (
	"fmt"
	"net"
	"strconv"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// VPNConfig 恰好持有服务端配置文件 "server.vpn" 键下的全部字段。
//
// 服务端在 VPN 组网里只有一个角色：内嵌 DERP 中继。它没有、也不需要 tailcat
// 客户端侧的 peers[]（那是节点配置的事），因此这里只有"DERP 对外是哪个
// host:port"一件事。设计见 docs/vpn-design.md 3.1、4.1。
//
// 这里刻意没有 derp_path：DERP 的挂载路径不可配。客户端侧
// derphttp.Client.urlString 把路径硬编码为 /derp
// （tailscale.com/derp/derphttp/derphttp_client.go:293），derpserver.Handler 也
// 文档化要求"mounted at /derp"并在内部分流绝对路径 /derp/probe 与
// /derp/latency-check（derp/derpserver/handler.go:28）。因此把它做成配置项只会
// 提供一个一改就让所有节点连不上的开关；单一事实来源是
// sharedconfig.DefaultVPNDERPPath。
type VPNConfig struct {
	// Enabled 表示在本服务端的 HTTPS 监听上挂载内嵌 DERP 中继。
	Enabled bool `json:"enabled"`

	// DERPAddr 是本服务端对外通告的 DERP host:port。未配置时由 domain 与
	// listen 的端口推导（见 ResolveDERPAddr）；当 DERP 经端口转发或反向代理
	// 暴露在与代理监听不同的 host:port 时必须显式给出。
	DERPAddr string `json:"derp_addr,omitempty"`
}

// ResolveDERPAddr 返回本服务端对外通告的 DERP host:port。
//
// 服务端没有 servers[]，默认值因此必须自己推导：host 取 server.domain，port 取
// server.listen 的端口——DERP 就挂在这个 HTTPS 监听上，客户端会用同一个
// host:port 建立 HTTP/1.1 Upgrade 连接。推导不出端口时（例如 listen 只写了
// 主机名）一律返回错误，由调用方让启动失败，**不退回任何猜测值**：一个猜错的
// 中继地址会让每个节点都连不上，而错误信息能直接告诉运维改用
// server.vpn.derp_addr。
func (fc *FileConfig) ResolveDERPAddr() (string, error) {
	if addr := fc.Server.VPN.DERPAddr; addr != "" {
		host, port, err := sharedconfig.SplitDERPAddr(addr)
		if err != nil {
			return "", fmt.Errorf("invalid server.vpn.derp_addr: %w", err)
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	if fc.Server.Domain == "" {
		return "", fmt.Errorf("cannot derive the DERP address: server.domain is empty; set server.vpn.derp_addr explicitly (host:port)")
	}
	port, err := sharedconfig.PortFromListen(fc.Server.Listen)
	if err != nil {
		return "", fmt.Errorf("cannot derive the DERP port from server.listen: %w; set server.vpn.derp_addr explicitly (host:port)", err)
	}
	return net.JoinHostPort(fc.Server.Domain, strconv.Itoa(port)), nil
}

// validateVPN 固定 VPN 的启动期契约，由 LoadConfig 在配置加载阶段调用，使这些
// 错误在进程启动时（而不是第一次有节点来连时）以明确的配置错误暴露出来。
//
// 只在 vpn.enabled 时校验：未启用的 VPN 配置不参与运行期，不应阻止服务端启动。
func (fc *FileConfig) validateVPN() error {
	if !fc.Server.VPN.Enabled {
		return nil
	}
	if _, err := fc.ResolveDERPAddr(); err != nil {
		return err
	}
	return nil
}
