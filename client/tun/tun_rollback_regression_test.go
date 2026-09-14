package tun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// TestCloseTunDevRunsTheCloseScript pins the rollback behind the TUN traffic
// loop: when the create script fails, Start() has to delete the routes the
// script may have installed before it failed.
//
// Only stopEngine ran on that path before. The tray then called Stop(), which
// returns early because m.running is still false, so the routes stayed in the
// system routing table and sent every packet into a TUN device nothing reads
// from.
//
// The rollback is exercised through the same helper Start() calls, with the
// close script replaced by one that leaves a marker file: removing the routes
// for real needs administrator rights and would rewrite the machine's network
// configuration, and what has to be proven here is that the cleanup runs at
// all. The platform close scripts themselves are covered by the helper tests.
func TestCloseTunDevRunsTheCloseScript(t *testing.T) {
	require.NotNil(t, scripts.CloseTunBytes, "this test needs the platform close script to be embedded")

	// unix runs the close script through pkexec unless the test is already
	// root, and a CI runner has no polkit agent to answer the prompt that
	// would have to appear. Running the check there would test the elevation,
	// not the rollback.
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && os.Geteuid() != 0 {
		t.Skip("running the close script needs root on unix")
	}

	origBytes, origName := scripts.CloseTunBytes, scripts.CloseTunFilename
	t.Cleanup(func() { scripts.CloseTunBytes, scripts.CloseTunFilename = origBytes, origName })

	marker := filepath.Join(t.TempDir(), "close-ran")
	scripts.CloseTunFilename = closeScriptName()
	scripts.CloseTunBytes = []byte(markerScript(marker))

	m := New(Config{
		Socks5Addr: "socks5://127.0.0.1:1",
		Device:     "tun-easyss-test",
		TunIP:      "198.18.0.1",
		TunGW:      "198.18.0.1",
		TunMask:    "255.255.0.0",
	})

	require.NoError(t, m.closeTunDevAndDelIPRoute())
	require.FileExists(t, marker,
		"the close script did not run: the routes of a failed TUN start would stay behind")
}

// closeScriptName returns a close script name the platform branch of
// closeTunDevAndDelIPRoute can hand to its interpreter.
func closeScriptName() string {
	if runtime.GOOS == "windows" {
		return "close_tun_dev_rollback_test.bat"
	}
	return "close_tun_dev_rollback_test.sh"
}

// markerScript returns a script in the language of the running platform that
// creates the marker file.
func markerScript(marker string) string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho. > \"" + marker + "\"\r\nexit /b 0\r\n"
	}
	return "#!/bin/sh\n: > \"" + marker + "\"\n"
}
