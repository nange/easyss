//go:build !android

package runner

// derpEnvProxySupported 报告本平台的 tailscale 构建是否会把 netns 拨号包进
// ALL_PROXY 指定的 SOCKS5 代理。
//
// 依据是 net/netns/socks.go 的构建标签 `!ios && !js && !android && !ts_omit_useproxy`：
// 桌面与服务器平台默认生效，Android（AAR）被排除。DERP 私有化依赖这条钩子，
// 因此在被排除的平台上必须明确拒绝启动 VPN，而不是让它退化成"连不上 DERP"。
func derpEnvProxySupported() bool { return true }
