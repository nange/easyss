//go:build linux

package util

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func SetSysDNS(v []string) error {
	if iface, err := defaultInterface(); err == nil {
		args := append([]string{"dns", iface}, v...)
		_, _ = Command("resolvectl", args...) // best-effort, ignore errors
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
	scanner.Scan() // skip header
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
	for _, line := range strings.Split(string(data), "\n") {
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
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			if s := strings.TrimSpace(strings.TrimPrefix(line, "nameserver")); s != "" {
				servers = append(servers, s)
			}
		}
	}
	return servers, nil
}

func SysDNSViaOSAScript() ([]string, error) {
	return nil, fmt.Errorf("SysDNSViaOSAScript is only supported on macOS")
}

func SetSysDNSViaOSAScript(servers []string) error {
	return fmt.Errorf("SetSysDNSViaOSAScript is only supported on macOS")
}
