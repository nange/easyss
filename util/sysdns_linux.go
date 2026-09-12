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

// tunDNSCommand runs the resolvectl invocations of the TUN DNS setup. It is a
// variable so that tests can assert the issued commands without touching the
// resolver of the machine running them.
var tunDNSCommand = func(name string, args ...string) (string, error) {
	return Command(name, args...)
}

// SetSysDNSForTun configures DNS resolution for TUN mode: the TUN device
// becomes the DNS default-route link with the resolver of its own, and the
// physical link stops being one.
//
// The per-link part is what makes resolution usable at all. systemd-resolved
// queries the resolver of a link with the socket pinned to that link's device,
// so the physical link's resolver sends its queries out of the physical NIC
// and therefore past the TUN routes: a public resolver cannot answer for a
// blocked domain, and the client then connects to whatever address the
// polluted path returned. Pinned to the TUN device, exactly the same query
// enters the tunnel instead, where easyss routes it by domain — direct for CN
// names, through the server for everything else.
func SetSysDNSForTun(tunDevice string, v []string) error {
	// The system DNS below is what programs that read /etc/resolv.conf or ask
	// for the link configuration keep using; it is best-effort like before.
	return errors.Join(setTunLinkDNS(tunDevice, v), SetSysDNS(v))
}

// EnsureSysDNSForTun re-asserts the TUN DNS state. NetworkManager rewrites a
// link's DNS settings when the connection changes (roaming, DHCP renew), and
// one of those rewrites makes the physical link the DNS default route again,
// which is the state that lets resolution bypass the tunnel.
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

// RestoreSysDNSForTun undoes SetSysDNSForTun. The TUN link's own settings
// disappear with the interface, so only the physical link has to be handed
// back to the resolver, besides restoring the servers the caller saved.
func RestoreSysDNSForTun(tunDevice string, origin []string) error {
	var errs []error

	// Best-effort: the interface is usually gone by now, which also drops the
	// per-link state below.
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

// setTunLinkDNS pins the resolver to the TUN device and keeps the physical
// link out of the DNS default route.
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

// resolvectlBool returns the trailing "yes"/"no" of a resolvectl setting
// output such as "Link 2 (eno1): no", so that a link name never matches.
func resolvectlBool(out string) string {
	idx := strings.LastIndex(out, ":")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(out[idx+1:])
}
