//go:build linux

package util

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

func SetSysDNS(v []string) error {
	if iface, err := defaultInterface(); err == nil {
		args := append([]string{"dns", iface}, v...)
		_, _ = Command("resolvectl", args...) // 尽力而为，忽略错误
	}
	return setResolvConf(v)
}

func SysDNS() ([]string, error) {
	iface, err := defaultInterface()
	if err != nil {
		return resolvConfServers()
	}

	out, err := Command("resolvectl", "dns", iface)
	if err == nil {
		if servers := parseResolvectlDNS(string(out)); len(servers) > 0 {
			return servers, nil
		}
	}

	return resolvConfServers()
}

func defaultInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Scan() // 跳过表头
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 8 && fields[1] == "00000000" && fields[3] == "0003" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("default interface not found")
}

var resolvectlDNSRe = regexp.MustCompile(`:\s*(.+)`)

func parseResolvectlDNS(output string) []string {
	m := resolvectlDNSRe.FindStringSubmatch(output)
	if len(m) < 2 {
		return nil
	}
	return strings.Fields(m[1])
}

func setResolvConf(servers []string) error {
	resolvPath := "/etc/resolv.conf"

	data, err := os.ReadFile(resolvPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvPath, err)
	}

	var lines []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nameserver") {
			continue
		}
		lines = append(lines, line)
	}
	for _, s := range servers {
		lines = append(lines, "nameserver "+s)
	}

	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(resolvPath, []byte(content), 0644)
}

func resolvConfServers() ([]string, error) {
	return sysDNSServersFromResolvConf("/etc/resolv.conf")
}

func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}

// tunDNSCommand 执行 TUN DNS 配置中的 resolvectl 调用。它是一个
// 变量，这样测试就能断言发出的命令，而无需触碰运行测试的机器的解析器。
var tunDNSCommand = func(name string, args ...string) (string, error) {
	return Command(name, args...)
}

// SetSysDNSForTun 为 TUN 模式配置 DNS 解析：TUN 设备成为 DNS 默认路由
// 链路并拥有自己的解析器，物理链路则不再是默认路由。
//
// 按链路（per-link）的配置才是让解析真正可用的关键。systemd-resolved
// 查询某条链路的解析器时，会把 socket 固定到该链路的设备上，
// 因此物理链路的解析器会从物理网卡发出查询，从而绕过 TUN 路由：
// 公共解析器无法回答被封锁的域名，客户端随后就会连接到被污染路径
// 返回的任意地址。而固定在 TUN 设备上时，完全相同的查询会进入隧道，
// 由 easyss 按域名路由 — 中国域名直连，其余域名走服务端。
func SetSysDNSForTun(tunDevice string, v []string) error {
	// 下面的系统 DNS 设置是那些读取 /etc/resolv.conf 或查询链路配置的
	// 程序仍在使用的解析器；和以往一样，这是尽力而为的操作。
	return errors.Join(setTunLinkDNS(tunDevice, v), SetSysDNS(v))
}

// EnsureSysDNSForTun 重新断言 TUN DNS 状态。NetworkManager 会在连接
// 变化（漫游、DHCP 续租）时重写链路的 DNS 设置，其中某次重写会让物理
// 链路重新成为 DNS 默认路由，而该状态会让解析绕过隧道。
func EnsureSysDNSForTun(tunDevice string, v []string) error {
	iface, err := defaultInterface()
	if err != nil {
		return fmt.Errorf("find default interface: %w", err)
	}

	out, err := tunDNSCommand("resolvectl", "default-route", iface)
	if err == nil && resolvectlBool(out) == "no" {
		return nil
	}
	return setTunLinkDNS(tunDevice, v)
}

// RestoreSysDNSForTun 撤销 SetSysDNSForTun 的效果。TUN 链路的设置会随
// 接口一起消失，因此除了恢复调用方保存的服务器外，只需把物理链路
// 交还给解析器。
func RestoreSysDNSForTun(tunDevice string, origin []string) error {
	var errs []error

	// 尽力而为：接口此时通常已经消失，下面的按链路状态也随之丢弃。
	if _, err := tunDNSCommand("resolvectl", "revert", tunDevice); err != nil {
		errs = append(errs, fmt.Errorf("resolvectl revert %s: %w", tunDevice, err))
	}
	if iface, err := defaultInterface(); err == nil {
		if _, err := tunDNSCommand("resolvectl", "default-route", iface, "yes"); err != nil {
			errs = append(errs, fmt.Errorf("resolvectl default-route %s yes: %w", iface, err))
		}
	}

	if len(origin) == 0 {
		return errors.Join(append(errs, SetSysDNS([]string{"empty"}))...)
	}
	curr, err := SysDNS()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if slices.Equal(curr, origin) {
		return errors.Join(errs...)
	}
	return errors.Join(append(errs, SetSysDNS(origin))...)
}

// setTunLinkDNS 把解析器固定到 TUN 设备，并让物理链路
// 不参与 DNS 默认路由。
func setTunLinkDNS(tunDevice string, v []string) error {
	iface, err := defaultInterface()
	if err != nil {
		return fmt.Errorf("find default interface: %w", err)
	}

	args := append([]string{"dns", tunDevice}, v...)
	if _, err := tunDNSCommand("resolvectl", args...); err != nil {
		return fmt.Errorf("resolvectl dns %s: %w", tunDevice, err)
	}

	for _, cmd := range [][]string{
		{"domain", tunDevice, "~."},
		{"default-route", tunDevice, "yes"},
		{"default-route", iface, "no"},
	} {
		if _, err := tunDNSCommand("resolvectl", cmd...); err != nil {
			return fmt.Errorf("resolvectl %s: %w", strings.Join(cmd, " "), err)
		}
	}
	return nil
}

// resolvectlBool 返回 resolvectl 设置输出（如 "Link 2 (eno1): no"）
// 末尾的 "yes"/"no"，这样链路名称永远不会被误匹配。
func resolvectlBool(out string) string {
	idx := strings.LastIndex(out, ":")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(out[idx+1:])
}
