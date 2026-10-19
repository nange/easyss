package tun

import (
	"runtime"
	"strconv"
	"strings"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// ScriptPlatform 标识一套平台脚本的位置参数布局。它显式存在（而不是直接读
// runtime.GOOS）是为了让测试能在任何主机上渲染**任意平台**的实参：仓库里
// linux 与 darwin 的脚本契约测试就是在同一台机器上用 bash/sh 跑对方平台的
// 脚本（见 cmd/easyss/tun_script_unix_test.go），只有本机平台可渲染时它们
// 就只能继续手写切片。
type ScriptPlatform string

const (
	PlatformLinux   ScriptPlatform = "linux"
	PlatformDarwin  ScriptPlatform = "darwin"
	PlatformWindows ScriptPlatform = "windows"
)

// ScriptArgs 是一次 TUN 会话交给平台创建/关闭脚本的全部输入。
//
// 它存在的唯一理由是：脚本的契约是**位置参数**，而三平台的位次并不相同
// （windows 的第 4 位是掩码、第 8 位是 DNS，linux/darwin 的第 2 位已经是
// 带前缀的地址，linux 不用 DNS 而 windows 不用 CIDR）。这些差异过去散落在
// 调用点的字面量切片里——client/tun 两条、提权 helper 两条、测试四条，任何
// 一处抄错都只会在运行时由脚本报 "failed near" 才暴露。
//
// 现在位置参数只在这里拼装：调用方填字段，Create/Close 按平台布局渲染。
// 归一化（地址前缀、IPv6 前缀长度、MTU 区间）也一并收进来，因为这三件事都是
// "脚本要求的形式"，而不是调用方的业务知识。
type ScriptArgs struct {
	// Dev 是本会话的设备与网关取值（见 Manager.DeviceConfig）。
	Dev DeviceConfig
	// DNSServer 只被 windows 创建脚本使用（netsh set dns），其余平台忽略；
	// 空值表示不改适配器 DNS。
	DNSServer string
	// MTU 是设备侧的 MTU，作为两个创建脚本的第 9 个位置参数。<=0 表示不传，
	// 脚本保留设备默认值（历史上只有 8 个实参的旧布局）。
	MTU int
}

// NewScriptArgs 用一份设备配置构造脚本实参。MTU 在这里归一化：它是跨进程
// 传递的值（helper 从 GET /tun 拿到），未配置的 0 必须落到与主进程相同的默认值。
func NewScriptArgs(dev DeviceConfig, dns string, mtu int) ScriptArgs {
	return ScriptArgs{Dev: dev, DNSServer: dns, MTU: sharedconfig.NormalizeTunMTU(mtu)}
}

// Platform 返回本次进程运行平台的布局。
func Platform() ScriptPlatform { return ScriptPlatform(runtime.GOOS) }

// Create 按本机平台的布局渲染创建脚本的实参。
func (a ScriptArgs) Create() []string { return a.CreateFor(Platform()) }

// Close 按本机平台的布局渲染关闭脚本的实参。
func (a ScriptArgs) Close() []string { return a.CloseFor(Platform()) }

// CreateFor 按给定平台的布局渲染创建脚本的位置参数：
//   - linux:   device, tun ip/prefix, tun gw, local gw, tun ipv6/prefix,
//     tun gw ipv6, server ipv6, local gw ipv6, mtu
//   - darwin:  同 linux，但第 5 位是**裸** IPv6 地址（脚本自己补 /64）
//   - windows: device, tun ip, tun gw, tun mask, tun ipv6/prefix,
//     tun gw ipv6, server ipv6, dns, mtu
func (a ScriptArgs) CreateFor(platform ScriptPlatform) []string {
	d := a.Dev
	mtu := strconv.Itoa(a.MTU)

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

// CloseFor 按给定平台的布局渲染关闭脚本的位置参数：
//   - linux/darwin: device, tun gw, local gw, tun gw ipv6, server ipv6, local gw ipv6
//     （linux 的脚本只读设备名，其余按统一顺序补齐——脚本带 set -u）
//   - windows:      device, tun gw, 裸 tun ipv6（netsh delete address 要不带前缀的地址）
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

// ipSub 把设备地址与掩码拼成脚本要的 CIDR 形式（"198.18.0.1/16"）。空值返回
// 空串：脚本据此跳过地址步骤，而不是拼出 "/" 这种非法实参。
func ipSub(ip, mask string) string {
	if ip == "" || mask == "" {
		return ""
	}
	return ip + "/" + mask
}

// bareV6Addr 从 "address/prefix" 形式的子网字符串中去掉前缀长度
// （"2001:db8::1/64" -> "2001:db8::1"）：darwin 创建脚本会自己补上 /64，
// windows 关闭脚本的 netsh delete address 要的也是裸地址。
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}
