package util

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
	"strings"
)

// NetworkInterface 获取系统的活动网络接口
// 参考：https://github.com/wzshiming/sysproxy/blob/5e86de4b71cf89f78bf95976d6ca35ea2e9ba526/sysproxy_darwin.go#L208
func NetworkInterface() (string, error) {
	buf, err := Command("sh", "-c", "networksetup -listnetworkserviceorder | grep -B 1 $(route -n get default | grep interface | awk '{print $2}')")
	if err != nil {
		return "", err
	}
	reader := textproto.NewReader(bufio.NewReader(bytes.NewBufferString(buf)))
	reg := regexp.MustCompile(`^\(\d+\)\s(.*)$`)
	device, err := reader.ReadLine()
	if err != nil {
		return "", err
	}
	match := reg.FindStringSubmatch(device)
	if len(match) <= 1 {
		return "", fmt.Errorf("unable to get network interface")
	}
	return match[1], nil
}

func SetSysDNS(v []string) error {
	ni, err := NetworkInterface()
	if err != nil {
		return err
	}
	_, err = Command("networksetup", append([]string{"-setdnsservers", ni}, v...)...)
	return err
}

func SysDNS() ([]string, error) {
	ret, err := sysDNSFromNetworkSetup()
	if err == nil && len(ret) > 0 {
		return ret, nil
	}

	// 当 networksetup 失败或返回空时，回退到 /etc/resolv.conf
	return sysDNSServersFromResolvConf("/etc/resolv.conf")
}

func sysDNSFromNetworkSetup() ([]string, error) {
	ni, err := NetworkInterface()
	if err != nil {
		return nil, err
	}
	buf, err := Command("networksetup", "-getdnsservers", ni)
	if err != nil {
		return nil, err
	}

	var ret []string
	reader := textproto.NewReader(bufio.NewReader(bytes.NewBufferString(buf)))
	for {
		ip, err := reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return ret, err
		}
		if IsIP(ip) {
			ret = append(ret, ip)
		}
	}

	return ret, nil
}

// SysDNSViaOSAScript 与 SysDNS 类似，但通过 osascript 以管理员权限运行，
// 适用于 macOS 上的非 root 进程。
func SysDNSViaOSAScript() ([]string, error) {
	ni, err := NetworkInterface()
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf(`networksetup -getdnsservers "%s"`, strings.ReplaceAll(ni, `"`, `\"`))
	out, err := runOSAScript(cmd)
	if err != nil {
		return nil, err
	}

	var ret []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if IsIP(ip) {
			ret = append(ret, ip)
		}
	}
	return ret, nil
}

// SetSysDNSViaOSAScript 与 SetSysDNS 类似，但通过 osascript 以管理员权限
// 运行，适用于 macOS 上的非 root 进程。
func SetSysDNSViaOSAScript(servers []string) error {
	ni, err := NetworkInterface()
	if err != nil {
		return err
	}

	var cmd string
	if len(servers) == 0 || (len(servers) == 1 && servers[0] == "empty") {
		cmd = fmt.Sprintf(`networksetup -setdnsservers "%s" Empty`, strings.ReplaceAll(ni, `"`, `\"`))
	} else {
		quoted := make([]string, len(servers))
		for i, s := range servers {
			quoted[i] = `"` + s + `"`
		}
		cmd = fmt.Sprintf(`networksetup -setdnsservers "%s" %s`,
			strings.ReplaceAll(ni, `"`, `\"`),
			strings.Join(quoted, " "))
	}
	_, err = runOSAScript(cmd)
	return err
}

// runOSAScript 通过 osascript 以管理员权限执行 shell 命令。
func runOSAScript(shellCmd string) (string, error) {
	escaped := strings.ReplaceAll(shellCmd, `"`, `\"`)
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, escaped)
	out, err := Command("osascript", "-e", script)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
