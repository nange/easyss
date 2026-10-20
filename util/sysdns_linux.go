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

// tunDNSCmd 执行一条 resolvectl 命令。TUN DNS 变更经由参数注入，测试因此可以断言
// 命令序列而不触碰本机解析器。
type tunDNSCmd func(name string, args ...string) (string, error)

// SetSysDNSForTun 为 TUN 模式配置 DNS 解析。按链路配置才是关键：systemd-resolved
// 查询某条链路的解析器时把 socket 固定到该链路的设备上，物理链路的解析器因此从
// 物理网卡发出查询、绕过 TUN，客户端会连到被污染路径返回的任意地址。
func SetSysDNSForTun(tunDevice string, v []string) error {
	// 仍要写系统 DNS：读 /etc/resolv.conf 或查询链路配置的程序走这条路径，尽力而为。
	return errors.Join(setTunLinkDNS(tunDevice, v, Command), SetSysDNS(v))
}

// EnsureSysDNSForTun 重新断言 TUN DNS 状态：NetworkManager 在漫游、DHCP 续租时
// 重写链路 DNS，其中一种重写会让物理链路重新成为 DNS 默认路由、解析绕过隧道。
func EnsureSysDNSForTun(tunDevice string, v []string) error {
	return ensureSysDNSForTun(tunDevice, v, Command)
}

func ensureSysDNSForTun(tunDevice string, v []string, run tunDNSCmd) error {
	iface, err := defaultInterface()
	if err != nil {
		return fmt.Errorf("find default interface: %w", err)
	}

	out, err := run("resolvectl", "default-route", iface)
	if err == nil && resolvectlBool(out) == "no" {
		return nil
	}
	return setTunLinkDNS(tunDevice, v, run)
}

// RestoreSysDNSForTun 撤销 SetSysDNSForTun：TUN 链路的设置随接口一起消失，
// 只需把物理链路交还给解析器并恢复调用方保存的服务器。
func RestoreSysDNSForTun(tunDevice string, origin []string) error {
	return restoreSysDNSForTun(tunDevice, origin, Command)
}

func restoreSysDNSForTun(tunDevice string, origin []string, run tunDNSCmd) error {
	var errs []error

	// 接口此时通常已消失，revert 失败属常态。
	if _, err := run("resolvectl", "revert", tunDevice); err != nil {
		errs = append(errs, fmt.Errorf("resolvectl revert %s: %w", tunDevice, err))
	}
	if iface, err := defaultInterface(); err == nil {
		if _, err := run("resolvectl", "default-route", iface, "yes"); err != nil {
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

// setTunLinkDNS 把解析器固定到 TUN 设备，并把物理链路移出 DNS 默认路由。
func setTunLinkDNS(tunDevice string, v []string, run tunDNSCmd) error {
	iface, err := defaultInterface()
	if err != nil {
		return fmt.Errorf("find default interface: %w", err)
	}

	args := append([]string{"dns", tunDevice}, v...)
	if _, err := run("resolvectl", args...); err != nil {
		return fmt.Errorf("resolvectl dns %s: %w", tunDevice, err)
	}

	for _, cmd := range [][]string{
		{"domain", tunDevice, "~."},
		{"default-route", tunDevice, "yes"},
		{"default-route", iface, "no"},
	} {
		if _, err := run("resolvectl", cmd...); err != nil {
			return fmt.Errorf("resolvectl %s: %w", strings.Join(cmd, " "), err)
		}
	}
	return nil
}

// resolvectlBool 只取输出（如 "Link 2 (eno1): no"）冒号后的 "yes"/"no"，
// 这样链路名称永远不会被误匹配。
func resolvectlBool(out string) string {
	_, after, ok := strings.CutLast(out, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(after)
}
