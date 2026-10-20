package tun

import (
	"runtime"
	"strconv"
	"strings"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// ScriptPlatform 标识一套平台脚本的位置参数布局；显式传入而非读 runtime.GOOS，是为了让
// 测试能在任何主机上渲染任意平台的实参。
type ScriptPlatform string

const (
	PlatformLinux   ScriptPlatform = "linux"
	PlatformDarwin  ScriptPlatform = "darwin"
	PlatformWindows ScriptPlatform = "windows"
)

// ScriptArgs 是一次 TUN 会话交给平台创建/关闭脚本的全部输入。脚本的契约是位置参数而三平台
// 位次不同（windows 的第 4 位是掩码、第 8 位是 DNS），抄错一个位次只会在运行时由脚本报
// "failed near" 才暴露。
type ScriptArgs struct {
	// Dev 是本会话的设备与网关取值（见 Manager.DeviceConfig）。
	Dev DeviceConfig
	// DNSServer 只被 windows 创建脚本使用（netsh set dns），空值表示不改适配器 DNS。
	DNSServer string
	// MTU 是设备侧的 MTU，作为创建脚本的第 9 个位置参数。非正值渲染为空串（unix 脚本用
	// ${9:-} 取值，空串跳过 MTU 步骤）：渲染成 "0" 会让脚本执行 "ip link set dev ... mtu 0"
	// 并整体失败。
	MTU int
}

// NewScriptArgs 构造脚本实参。MTU 要跨进程传递（helper 从 GET /tun 拿到），未配置的 0 必须
// 落到与主进程相同的默认值。
func NewScriptArgs(dev DeviceConfig, dns string, mtu int) ScriptArgs {
	return ScriptArgs{Dev: dev, DNSServer: dns, MTU: sharedconfig.NormalizeTunMTU(mtu)}
}

func Platform() ScriptPlatform { return ScriptPlatform(runtime.GOOS) }

func (a ScriptArgs) Create() []string { return a.CreateFor(Platform()) }

func (a ScriptArgs) Close() []string { return a.CloseFor(Platform()) }

// CreateFor 按给定平台的布局渲染创建脚本的位置参数，darwin 的第 5 位是裸 IPv6 地址。
func (a ScriptArgs) CreateFor(platform ScriptPlatform) []string {
	d := a.Dev
	mtu := ""
	if a.MTU > 0 {
		mtu = strconv.Itoa(a.MTU)
	}

	switch platform {
	case PlatformLinux:
		return []string{
			d.Device, ipSub(d.TunIP, d.TunMask), d.TunGW, d.LocalGateway,
			d.TunIPV6Sub, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6, mtu,
		}
	case PlatformWindows:
		return []string{
			d.Device, d.TunIP, d.TunGW, d.TunMask, d.TunIPV6Sub, d.TunGWV6,
			d.ServerIPV6, a.DNSServer, mtu,
		}
	case PlatformDarwin:
		return []string{
			d.Device, d.TunIP, d.TunGW, d.LocalGateway,
			bareV6Addr(d.TunIPV6Sub), d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6, mtu,
		}
	default:
		return nil
	}
}

// CloseFor 按给定平台的布局渲染关闭脚本的位置参数：linux 脚本只读设备名，补齐的
// 实参无害；windows 的 netsh delete address 要不带前缀长度的裸地址。
func (a ScriptArgs) CloseFor(platform ScriptPlatform) []string {
	d := a.Dev

	switch platform {
	case PlatformLinux, PlatformDarwin:
		return []string{
			d.Device, d.TunGW, d.LocalGateway, d.TunGWV6, d.ServerIPV6, d.LocalGatewayV6,
		}
	case PlatformWindows:
		return []string{d.Device, d.TunGW, bareV6Addr(d.TunIPV6Sub)}
	default:
		return nil
	}
}

// ipSub 把设备地址与掩码拼成脚本要的 CIDR 形式。空值返回空串，避免拼出 "/" 这种非法实参。
func ipSub(ip, mask string) string {
	if ip == "" || mask == "" {
		return ""
	}
	return ip + "/" + mask
}

// bareV6Addr 去掉子网字符串的前缀长度：darwin 创建脚本自己补 /64，windows 的 netsh delete
// address 也要裸地址。
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}
