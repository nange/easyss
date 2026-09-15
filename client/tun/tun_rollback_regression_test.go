package tun

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// errCreateFailed is what a stubbed create script reports: the platform script
// rejected a command and exited non-zero, which is the contract the unix and
// Windows create scripts now implement.
var errCreateFailed = errors.New("tun: exec create script: exit status 1")

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
// close script replaced by one that records its arguments into a marker file:
// removing the routes for real needs administrator rights and would rewrite
// the machine's network configuration, and what has to be proven here is
// that the cleanup runs at all, and with the arguments the platform scripts
// need. The platform close scripts themselves are covered by the helper
// tests.
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
		TunIPV6Sub: "2001:db8::1/64",
	})

	require.NoError(t, m.closeTunDevAndDelIPRoute())
	content, err := os.ReadFile(marker)
	require.NoError(t, err, "the close script did not run: the routes of a failed TUN start would stay behind")
	require.Contains(t, string(content), "tun-easyss-test")
	if runtime.GOOS == "windows" {
		// The third argument is the bare v6 address (no /64): netsh delete
		// address takes the plain address, and the create script's
		// "add address" cannot re-apply the persistent v6 address while it
		// is still on the adapter.
		require.Contains(t, string(content), "2001:db8::1")
		require.NotContains(t, string(content), "/64")
	}
}

// TestStartRollbackAfterCreateFailure drives the whole Start() failure path
// through the package hooks: the create script exits non-zero, which is what
// the platform scripts now report (see the exit code contract in
// create_tun_dev.sh, create_tun_dev_darwin.sh and create_tun_dev_windows.bat),
// and Start() has to undo everything it already touched.
//
// This is the cross-platform counterpart of TestCloseTunDevRunsTheCloseScript:
// that one proves the close script is invoked with the right arguments on the
// platform it runs on, this one proves the rollback happens at all, in order,
// and includes the system DNS that the same failure used to leave pointing at
// the TUN resolver. It replaces the engine, the scripts and the DNS setup with
// hooks because the real ones need a TUN device, administrator rights and a
// live proxy — and would reconfigure the network of the machine running it.
func TestStartRollbackAfterCreateFailure(t *testing.T) {
	var order []string

	stubStartHooks(t)
	saveAndSetDNSStepFn = func(m *Manager) error {
		order = append(order, "save-dns")
		// What saveAndSetDNSStep records once it has touched the system DNS.
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = true
		return nil
	}
	createTunDevFn = func(*Manager) error {
		order = append(order, "create")
		return errCreateFailed
	}
	closeTunDevFn = func(*Manager) error {
		order = append(order, "close")
		return nil
	}
	restoreDNSStepFn = func(m *Manager) error {
		order = append(order, "restore-dns")
		require.True(t, m.dnsChanged,
			"the failure path must restore the DNS it changed, and dnsChanged is what restoreDNSStep acts on")
		return nil
	}

	// Windows configures the adapter DNS from its own scripts and never
	// touches the system DNS, so its failure path has no DNS step to run.
	want := []string{"create", "close"}
	if manageSystemDNS() {
		want = []string{"save-dns", "create", "close", "restore-dns"}
	}

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})

	err := m.Start()
	require.Error(t, err, "a failed create script must fail the start")
	require.Contains(t, err.Error(), "create device", "the error has to name the failed step so the tray can report it")
	require.False(t, m.IsRunning(), "a failed start must not report a running tunnel")

	require.Equal(t, want, order,
		"the failure path has to stop the engine, delete the routes the script may have installed, and put the system DNS back")
}

// TestStartRollbackSkipsUntouchedDNS is the other half of the DNS rollback: a
// start that never reconfigured the system DNS must not have it written back.
// On darwin an untouched system is restored as "empty", which would clear the
// DHCP-provided servers instead of leaving them alone.
func TestStartRollbackSkipsUntouchedDNS(t *testing.T) {
	if !manageSystemDNS() {
		t.Skip("this platform does not switch the system DNS for TUN")
	}

	var restoreCalled bool

	stubStartHooks(t)
	saveAndSetDNSStepFn = func(m *Manager) error {
		// darwin with a hand-configured DNS: nothing is changed, so nothing
		// has to be restored.
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = false
		return nil
	}
	createTunDevFn = func(*Manager) error { return errCreateFailed }
	closeTunDevFn = func(*Manager) error { return nil }
	restoreDNSStepFn = func(*Manager) error {
		restoreCalled = true
		return nil
	}

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	require.Error(t, m.Start())

	require.True(t, restoreCalled, "the failure path calls the restore step")
	require.False(t, m.dnsChanged, "a start that did not change the system DNS must not have it restored")
}

// TestStartCreateScriptFailureEndToEnd exercises the real script plumbing: the
// embedded create script is replaced by one that fails, and the failure has to
// come back out of Start() as an error naming the step, with the close script
// run afterwards.
//
// It needs to run the script through the interpreter the platform uses, and
// without root that is pkexec on linux and "osascript ... with administrator
// privileges" on darwin: a test runner has no polkit agent and no
// authorization dialogue to answer, so the script would never run at all (and
// the darwin run would sit out the 60s create and 30s close timeouts). The
// exit code contract itself is covered without root by
// cmd/easyss/tun_script_unix_test.go, and cmd.exe by
// tun_script_windows_test.go, so this end-to-end check is left to a run that
// already is root.
func TestStartCreateScriptFailureEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the replacement scripts are POSIX shell scripts; cmd.exe is covered by tun_script_windows_test.go")
	}
	if os.Geteuid() != 0 {
		t.Skip("the create script runs through pkexec/osascript without root, which a test runner cannot authorize")
	}

	origCreateBytes, origCreateName := scripts.CreateTunBytes, scripts.CreateTunFilename
	origCloseBytes, origCloseName := scripts.CloseTunBytes, scripts.CloseTunFilename
	t.Cleanup(func() {
		scripts.CreateTunBytes, scripts.CreateTunFilename = origCreateBytes, origCreateName
		scripts.CloseTunBytes, scripts.CloseTunFilename = origCloseBytes, origCloseName
	})

	dir := t.TempDir()
	createRan := filepath.Join(dir, "create-ran")
	closeRan := filepath.Join(dir, "close-ran")
	scripts.CreateTunFilename = "create_tun_dev_test.sh"
	scripts.CreateTunBytes = []byte("#!/bin/sh\necho ran > \"" + createRan + "\"\nexit 1\n")
	scripts.CloseTunFilename = "close_tun_dev_test.sh"
	scripts.CloseTunBytes = []byte("#!/bin/sh\necho ran > \"" + closeRan + "\"\n")

	stubStartHooks(t)
	// The real implementations have to run here: this test exercises the
	// script plumbing (writing the embedded script, running it through the
	// platform interpreter, reading back its exit code), which is what the
	// failing stub above replaces. Never a no-op.
	createTunDevFn = func(m *Manager) error { return m.createTunDevAndSetIPRoute() }
	closeTunDevFn = func(m *Manager) error { return m.closeTunDevAndDelIPRoute() }

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	err := m.Start()
	require.Error(t, err, "the create script exited 1: Start must not report a running tunnel")
	require.Contains(t, err.Error(), "create device")

	_, statErr := os.Stat(createRan)
	require.NoError(t, statErr, "the create script did not run")
	_, statErr = os.Stat(closeRan)
	require.NoError(t, statErr, "the close script did not run: the routes of the failed start would stay behind")
}

// stubStartHooks replaces the engine, the settle delay, the DNS steps and the
// platform scripts with no-op hooks, and restores every hook it touched when
// the test ends. It keeps a test from starting tun2socks for real (which would
// open a TUN device and need administrator rights) and from waiting out the
// device settle pause; a test that needs a hook to do something assigns it
// after this call.
func stubStartHooks(t *testing.T) {
	t.Helper()

	origStart, origStop := engineStartFn, engineStopFn
	origDelay := settleDelay
	origSave, origRestore := saveAndSetDNSStepFn, restoreDNSStepFn
	origCreate, origClose := createTunDevFn, closeTunDevFn

	engineStartFn = func() error { return nil }
	engineStopFn = func(string) {}
	settleDelay = func() {}
	saveAndSetDNSStepFn = func(*Manager) error { return nil }
	restoreDNSStepFn = func(*Manager) error { return nil }
	createTunDevFn = func(*Manager) error { return nil }
	closeTunDevFn = func(*Manager) error { return nil }

	t.Cleanup(func() {
		engineStartFn, engineStopFn = origStart, origStop
		settleDelay = origDelay
		saveAndSetDNSStepFn, restoreDNSStepFn = origSave, origRestore
		createTunDevFn, closeTunDevFn = origCreate, origClose
	})
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
// records its arguments into the marker file.
func markerScript(marker string) string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho %* > \"" + marker + "\"\r\nexit /b 0\r\n"
	}
	return "#!/bin/sh\necho \"$@\" > \"" + marker + "\"\n"
}
