//go:build android

package runner

// derpEnvProxySupported 在 Android 上返回 false：tailscale 的 netns SOCKS5 包装
// 被 `!android` 构建标签排除（见 net/netns/socks.go），ALL_PROXY 不会生效，
// 而 DERP 私有化正依赖它（见 derpshim.go）。
func derpEnvProxySupported() bool { return false }
