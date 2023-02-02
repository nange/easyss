package util

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"regexp"
)

// NetworkInterface get the active network interface of system
// Ref:https://github.com/wzshiming/sysproxy/blob/5e86de4b71cf89f78bf95976d6ca35ea2e9ba526/sysproxy_darwin.go#L208
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
