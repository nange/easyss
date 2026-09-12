//go:build linux && !headless

package main

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

const sysProxyEnvDump = `LANG=en_US.UTF-8
http_proxy=http://old.example:1234
NO_PROXY=example.com
PATH=/usr/bin
`

type recordedProxyEnvCmd struct {
	name string
	args []string
}

// installProxyEnvExec replaces the command runner for the duration of the test
// and collects every command that is issued.
func installProxyEnvExec(t *testing.T, run func(name string, args []string) (string, error)) *[]recordedProxyEnvCmd {
	t.Helper()

	cmds := &[]recordedProxyEnvCmd{}

	original := proxyEnvExec
	t.Cleanup(func() { proxyEnvExec = original })

	proxyEnvExec = func(name string, args ...string) (string, error) {
		*cmds = append(*cmds, recordedProxyEnvCmd{name: name, args: slices.Clone(args)})
		return run(name, args)
	}

	return cmds
}

// stubProxyEnvExec succeeds for every command, serving dump for
// `systemctl --user show-environment`; fail makes every command fail instead.
func stubProxyEnvExec(t *testing.T, dump string, fail bool) *[]recordedProxyEnvCmd {
	t.Helper()

	return installProxyEnvExec(t, func(name string, args []string) (string, error) {
		if fail {
			return "", fmt.Errorf("%s: unavailable", name)
		}
		if name == "systemctl" && slices.Contains(args, "show-environment") {
			return dump, nil
		}
		return "", nil
	})
}

// stubFailingCommand lets only failName fail, so that the fallback to the other
// environment store can be exercised.
func stubFailingCommand(t *testing.T, failName string) *[]recordedProxyEnvCmd {
	t.Helper()

	return installProxyEnvExec(t, func(name string, args []string) (string, error) {
		if name == "systemctl" && slices.Contains(args, "show-environment") {
			return sysProxyEnvDump, nil
		}
		if name == failName {
			return "", fmt.Errorf("%s: unavailable", name)
		}
		return "", nil
	})
}

func resetSysProxyEnvState(t *testing.T) {
	t.Helper()

	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	sysProxyEnv.previous = nil
	sysProxyEnv.store = proxyEnvStoreNone
}

func sysProxyAssignments(port int) []string {
	values := sysProxyEnvValues(port)

	assignments := make([]string, 0, len(sysProxyEnvKeys))
	for _, key := range sysProxyEnvKeys {
		assignments = append(assignments, key+"="+values[key])
	}
	return assignments
}

// findProxyEnvCmd returns the arguments of the recorded command whose name
// matches and whose arguments contain every wanted element.
func findProxyEnvCmd(cmds []recordedProxyEnvCmd, name string, wanted ...string) []string {
	for _, cmd := range cmds {
		if cmd.name != name {
			continue
		}
		hasAll := true
		for _, want := range wanted {
			if !slices.Contains(cmd.args, want) {
				hasAll = false
				break
			}
		}
		if hasAll {
			return cmd.args
		}
	}
	return nil
}

// assertNoDBusSystemdFlag guards the split between the two environment stores:
// passing --systemd to dbus-update-activation-environment makes it write to the
// systemd user manager as well, where it would re-create the variables that
// `systemctl unset-environment` just removed.
func assertNoDBusSystemdFlag(t *testing.T, cmds []recordedProxyEnvCmd) {
	t.Helper()

	for _, cmd := range cmds {
		if cmd.name == "dbus-update-activation-environment" && slices.Contains(cmd.args, "--systemd") {
			t.Fatalf("dbus-update-activation-environment must not use --systemd, got %v", cmd.args)
		}
	}
}

func TestSysProxyEnvValuesCoverEveryKey(t *testing.T) {
	values := sysProxyEnvValues(5080)

	if len(values) != len(sysProxyEnvKeys) {
		t.Fatalf("values cover %d keys, sysProxyEnvKeys lists %d", len(values), len(sysProxyEnvKeys))
	}
	for _, key := range sysProxyEnvKeys {
		if _, ok := values[key]; !ok {
			t.Fatalf("no value for key %q", key)
		}
	}

	const addr = "http://127.0.0.1:5080"
	for _, key := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if values[key] != addr {
			t.Fatalf("%s = %q, want %q", key, values[key], addr)
		}
	}
	for _, key := range []string{"no_proxy", "NO_PROXY"} {
		if values[key] != sysProxyNoProxy {
			t.Fatalf("%s = %q, want %q", key, values[key], sysProxyNoProxy)
		}
	}
}

func TestSetSysProxyEnvPublishesToSystemdUserManager(t *testing.T) {
	resetSysProxyEnvState(t)
	cmds := stubProxyEnvExec(t, sysProxyEnvDump, false)

	applied, err := setSysProxyEnv(5080)
	if err != nil {
		t.Fatalf("setSysProxyEnv: %v", err)
	}
	if !applied {
		t.Fatal("setSysProxyEnv reported that nothing was applied")
	}

	wanted := append([]string{"--user", "set-environment"}, sysProxyAssignments(5080)...)
	if args := findProxyEnvCmd(*cmds, "systemctl", wanted...); args == nil {
		t.Fatalf("systemd user manager not updated, commands: %v", *cmds)
	}

	// One store is enough: publishing to D-Bus as well would duplicate the work
	// and, with dbus-broker, target the very same environment.
	if args := findProxyEnvCmd(*cmds, "dbus-update-activation-environment"); args != nil {
		t.Fatalf("D-Bus activation environment updated although systemd worked: %v", args)
	}
}

func TestUnsetSysProxyEnvRestoresPreviousValues(t *testing.T) {
	resetSysProxyEnvState(t)
	cmds := stubProxyEnvExec(t, sysProxyEnvDump, false)

	if _, err := setSysProxyEnv(5080); err != nil {
		t.Fatalf("setSysProxyEnv: %v", err)
	}
	*cmds = nil

	applied, err := unsetSysProxyEnv()
	if err != nil {
		t.Fatalf("unsetSysProxyEnv: %v", err)
	}
	if !applied {
		t.Fatal("unsetSysProxyEnv reported that nothing was restored")
	}

	// The variables that existed before easyss started are put back.
	restored := []string{"http_proxy=http://old.example:1234", "NO_PROXY=example.com"}
	if args := findProxyEnvCmd(*cmds, "systemctl", append([]string{"--user", "set-environment"}, restored...)...); args == nil {
		t.Fatalf("previous values not restored, commands: %v", *cmds)
	}

	// The ones easyss introduced are removed again.
	unsetArgs := findProxyEnvCmd(*cmds, "systemctl", "--user", "unset-environment")
	if unsetArgs == nil {
		t.Fatalf("variables not unset, commands: %v", *cmds)
	}
	for _, key := range []string{"https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if !slices.Contains(unsetArgs, key) {
			t.Fatalf("%s not unset, got %v", key, unsetArgs)
		}
	}
	for _, key := range []string{"http_proxy", "NO_PROXY"} {
		if slices.Contains(unsetArgs, key) {
			t.Fatalf("%s was unset even though it existed before, got %v", key, unsetArgs)
		}
	}

	if args := findProxyEnvCmd(*cmds, "dbus-update-activation-environment"); args != nil {
		t.Fatalf("D-Bus activation environment touched although systemd was used: %v", args)
	}
	assertNoDBusSystemdFlag(t, *cmds)
}

func TestSetSysProxyEnvFallsBackToDBus(t *testing.T) {
	resetSysProxyEnvState(t)
	cmds := stubFailingCommand(t, "systemctl")

	applied, err := setSysProxyEnv(5080)
	if err != nil {
		t.Fatalf("setSysProxyEnv: %v", err)
	}
	if !applied {
		t.Fatal("setSysProxyEnv did not fall back to the D-Bus activation environment")
	}

	if args := findProxyEnvCmd(*cmds, "dbus-update-activation-environment", sysProxyAssignments(5080)...); args == nil {
		t.Fatalf("D-Bus activation environment not updated, commands: %v", *cmds)
	}
	assertNoDBusSystemdFlag(t, *cmds)

	*cmds = nil

	if _, err := unsetSysProxyEnv(); err != nil {
		t.Fatalf("unsetSysProxyEnv: %v", err)
	}

	// dbus-daemon cannot remove a variable, so the pre-existing value is put
	// back and the ones easyss added are emptied instead.
	wanted := []string{"http_proxy=http://old.example:1234", "https_proxy=", "NO_PROXY=example.com"}
	if args := findProxyEnvCmd(*cmds, "dbus-update-activation-environment", wanted...); args == nil {
		t.Fatalf("D-Bus activation environment not restored, commands: %v", *cmds)
	}
	if args := findProxyEnvCmd(*cmds, "systemctl", "--user", "unset-environment"); args != nil {
		t.Fatalf("systemd was updated although the D-Bus store was used: %v", args)
	}
}

func TestUnsetSysProxyEnvWithoutApplyIsNoop(t *testing.T) {
	resetSysProxyEnvState(t)
	cmds := stubProxyEnvExec(t, sysProxyEnvDump, false)

	applied, err := unsetSysProxyEnv()
	if err != nil {
		t.Fatalf("unsetSysProxyEnv: %v", err)
	}
	if applied {
		t.Fatal("unsetSysProxyEnv claimed to restore something without a preceding set")
	}
	if len(*cmds) != 0 {
		t.Fatalf("unexpected commands: %v", *cmds)
	}
}

func TestSetSysProxyEnvReportsFailureWhenNoStoreIsReachable(t *testing.T) {
	resetSysProxyEnvState(t)
	stubProxyEnvExec(t, sysProxyEnvDump, true)

	applied, err := setSysProxyEnv(5080)
	if applied {
		t.Fatal("setSysProxyEnv reported success although every command failed")
	}
	if err == nil {
		t.Fatal("expected an error when no environment store could be updated")
	}

	// A failed set must not make a later unset believe it has something to do.
	unsetApplied, unsetErr := unsetSysProxyEnv()
	if unsetApplied || unsetErr != nil {
		t.Fatalf("unsetSysProxyEnv = (%v, %v), want (false, nil)", unsetApplied, unsetErr)
	}
}

func TestUnsetSysProxyEnvKeepsStateWhenRestoreFails(t *testing.T) {
	resetSysProxyEnvState(t)

	failSystemd := false
	installProxyEnvExec(t, func(name string, args []string) (string, error) {
		if name == "systemctl" && slices.Contains(args, "show-environment") {
			return sysProxyEnvDump, nil
		}
		if name == "systemctl" && failSystemd {
			return "", errors.New("systemd gone")
		}
		return "", nil
	})

	if _, err := setSysProxyEnv(5080); err != nil {
		t.Fatalf("setSysProxyEnv: %v", err)
	}

	failSystemd = true
	if applied, err := unsetSysProxyEnv(); applied || err == nil {
		t.Fatalf("unsetSysProxyEnv = (%v, %v), want a failure", applied, err)
	}

	// The snapshot survives the failure, so a retry -- the tray reverts its
	// checkmark and lets the user click again -- can still restore the values.
	failSystemd = false
	applied, err := unsetSysProxyEnv()
	if err != nil {
		t.Fatalf("retry of unsetSysProxyEnv: %v", err)
	}
	if !applied {
		t.Fatal("retry of unsetSysProxyEnv restored nothing")
	}
}
