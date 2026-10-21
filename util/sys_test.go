package util

import (
	"net"
	"runtime"
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/stretchr/testify/assert"
)

func TestSysGatewayAndDevice(t *testing.T) {
	gw, dev, err := SysGatewayAndDevice()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		assert.Nil(t, err)
		assert.NotEmpty(t, gw)
		assert.NotEmpty(t, dev)
	default:
		t.SkipNow()
	}
}

func TestSysDefaultRoute(t *testing.T) {
	// 只有 Windows 读取路由表；darwin/linux 使用 0.0.0.1 探测
	// （参见 SysGatewayAndDevice）。
	if runtime.GOOS != "windows" {
		t.SkipNow()
	}
	iface, gw, err := SysDefaultRoute()
	assert.Nil(t, err)
	assert.NotNil(t, iface)
	assert.NotNil(t, gw)
	if iface != nil {
		assert.NotEmpty(t, iface.Name)
		assert.False(t, IsTunIface(iface), "default interface must not be the easyss TUN device")
		assert.True(t, iface.Flags&net.FlagUp != 0, "default interface should be up")
	}
}

func TestSysGatewayAndDeviceV6(t *testing.T) {
	gw, dev, err := SysGatewayAndDeviceV6()
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if err == nil {
			assert.NotEmpty(t, gw)
			assert.NotEmpty(t, dev)
		}
	default:
		t.SkipNow()
	}
}

func TestIsTunSubnetAddr(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"198.18.0.1", true}, // 默认 TunIP
		{"198.18.255.255", true},
		{"198.19.255.255", true}, // /15 上界
		{"198.17.255.255", false},
		{"198.20.0.1", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
	}
	for _, c := range cases {
		if got := IsTunSubnetAddr(net.ParseIP(c.ip)); got != c.want {
			t.Fatalf("IsTunSubnetAddr(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIsTunIface(t *testing.T) {
	// 基于名称的匹配是确定性的，并且会在任何 OS 地址查询之前短路。
	// 无论测试运行在哪个平台，两个平台的默认名称都必须被识别。
	for _, name := range []string{
		config.DefaultTunDeviceName,
		config.DefaultTunDeviceNameDarwin,
	} {
		if !IsTunIface(&net.Interface{Name: name}) {
			t.Fatalf("expected %s to be recognized as the TUN device", name)
		}
	}
	// Index 取一个不可能存在的值：darwin 上 Index 为 0 会让 Addrs() 返回所有主机
	// 接口的地址（含 TUN 的 198.18.0.1），反向断言就失去意义了。
	if IsTunIface(&net.Interface{Name: "Ethernet", Index: 1 << 24}) {
		t.Fatal("expected a plain interface name to not be recognized")
	}
	if IsTunIface(nil) {
		t.Fatal("expected nil interface to not be recognized")
	}
}
