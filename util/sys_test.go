package util

import (
	"net"
	"runtime"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/stretchr/testify/assert"
)

func TestSysSupportPowershell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.SkipNow()
	}
	s := SysSupportPowershell()
	assert.True(t, s)
}

func TestSysPowershellMajorVersion(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.SkipNow()
	}
	v := SysPowershellMajorVersion()
	assert.GreaterOrEqual(t, v, 0)
}

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
		sharedconfig.DefaultTunDeviceName,
		sharedconfig.DefaultTunDeviceNameDarwin,
	} {
		if !IsTunIface(&net.Interface{Name: name}) {
			t.Fatalf("expected %s to be recognized as the TUN device", name)
		}
	}
	// 给合成的接口一个不可能存在的 Index：在 darwin 上 Index 为 0
	// 会使 Addrs() 返回所有主机接口的地址（包括 easyss TUN 设备
	// 启动时的 198.18.0.1），这会错误地触发下面的子网匹配。
	// 不存在的 Index 会让 Addrs() 在所有平台上返回空，
	// 因此无论主机接口状态如何，这个反向断言都成立。
	if IsTunIface(&net.Interface{Name: "Ethernet", Index: 1 << 24}) {
		t.Fatal("expected a plain interface name to not be recognized")
	}
	if IsTunIface(nil) {
		t.Fatal("expected nil interface to not be recognized")
	}
}
