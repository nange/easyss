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
	// Only Windows reads the routing table; darwin/linux use the 0.0.0.1
	// probe (see SysGatewayAndDevice).
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
		{"198.18.0.1", true},   // default TunIP
		{"198.18.255.255", true},
		{"198.19.255.255", true}, // /15 upper bound
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
	// Name-based match is deterministic and short-circuits before any
	// OS address lookup. Both platform default names must be recognized
	// regardless of the platform the test runs on.
	for _, name := range []string{
		sharedconfig.DefaultTunDeviceName,
		sharedconfig.DefaultTunDeviceNameDarwin,
	} {
		if !IsTunIface(&net.Interface{Name: name}) {
			t.Fatalf("expected %s to be recognized as the TUN device", name)
		}
	}
	if IsTunIface(&net.Interface{Name: "Ethernet"}) {
		t.Fatal("expected a plain interface name to not be recognized")
	}
	if IsTunIface(nil) {
		t.Fatal("expected nil interface to not be recognized")
	}
}
