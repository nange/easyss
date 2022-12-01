package util

import (
	"bytes"
	"net"
	"os/exec"
	"strconv"

	netroute "github.com/libp2p/go-netroute"
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

func SysGatewayAndDevice() (gw string, dev string, err error) {
	r, _ := netroute.New()
	iface, gateway, _, err := r.Route(net.IPv4(119, 29, 29, 29))
	if err != nil {
		return "", "", err
	}

	return gateway.String(), iface.Name, nil
}
