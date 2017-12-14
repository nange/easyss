package utils

import (
	"bytes"
	"os/exec"
	"strconv"
)

func SysSupportPowershell() bool {
	cmd := exec.Command("powershell")
	if err := cmd.Start(); err != nil {
		return false
	}
	return true
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
