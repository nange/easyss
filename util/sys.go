package util

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

func SysSupportPowershell() bool {
	lp, err := exec.LookPath("powershell")
	if lp != "" && err == nil {
		return true
	}
	return false
}

func SysPowershellMajorVersion() int {
	cmd := exec.Command("powershell", "-Command", "$PSVersionTable.PSVersion")
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return 0
	}
	bs := buf.Bytes()
	if len(bs) < 64 {
		return 0
	}
	v, _ := strconv.ParseInt(string(bs[64]), 10, 32)
	return int(v)
}

func SysIPRouteList() ([]string, error) {
	cmd := exec.Command("ip", "route")
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var lines []string
	br := bufio.NewReader(bytes.NewReader(b))
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		lines = append(lines, string(line))
	}

	return lines, nil
}

func SysDefaultRoute() ([]string, error) {
	list, err := SysIPRouteList()
	if err != nil {
		return nil, err
	}

	var defaultList []string
	for _, l := range list {
		if strings.HasPrefix(l, "default") {
			defaultList = append(defaultList, l)
		}
	}

	return defaultList, nil
}

func SysGatewayAndDevice() (gw string, dev string, err error) {
	list, err := SysDefaultRoute()
	if err != nil {
		return "", "", err
	}
	if len(list) == 0 {
		return "", "", nil
	}

	dr := list[len(list)-1]
	items := strings.Split(dr, " ")
	for i := 0; i < len(items); i++ {
		if items[i] == "via" {
			gw = items[i+1]
			continue
		}
		if items[i] == "dev" {
			dev = items[i+1]
			continue
		}
	}

	return
}
