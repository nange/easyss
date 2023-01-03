package util

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSysSupportPowershell(t *testing.T) {
	s := SysSupportPowershell()
	if runtime.GOOS == "windows" {
		assert.True(t, s)
	} else {
		assert.False(t, s)
	}
}

func TestSysPowershellMajorVersion(t *testing.T) {
	v := SysPowershellMajorVersion()
	if runtime.GOOS == "windows" {
		assert.Greater(t, v, 3)
	} else {
		assert.Equal(t, 0, v)
	}
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
