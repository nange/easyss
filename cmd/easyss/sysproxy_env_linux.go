//go:build linux && !headless

package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

const (
	// sysProxyNoProxy keeps traffic to the local machine itself out of the
	// proxy. Without it a request for http://127.0.0.1:<http_port>/stats would
	// be sent to the proxy listening at that very address.
	sysProxyNoProxy = "localhost,127.0.0.1,::1"

	// proxyEnvTimeout bounds the external commands below so that an
	// unresponsive session bus cannot block startup or the tray.
	proxyEnvTimeout = 5 * time.Second
)

// sysProxyEnvKeys lists every variable easyss publishes and restores.
//
// Programs pick the proxy source based on the desktop environment they detect:
// Chromium reads gsettings on GNOME and kioslaverc on KDE, but on any other
// desktop (Hyprland, sway, ...) it ignores the system settings entirely and
// only looks at these environment variables. Publishing them to the session
// environment therefore closes the gap that leaves a browser on a plain
// Hyprland session talking directly to the internet.
var sysProxyEnvKeys = []string{
	"http_proxy", "https_proxy", "no_proxy",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
}

// proxyEnvStore identifies where setSysProxyEnv published the proxy.
type proxyEnvStore int

const (
	proxyEnvStoreNone proxyEnvStore = iota
	proxyEnvStoreSystemd
	proxyEnvStoreDBus
)

// proxyEnvCmd is a single external command that reads or updates the session
// environment.
type proxyEnvCmd struct {
	name string
	args []string
}

// proxyEnvExec runs such a command. It is a variable so that tests can observe
// the commands being issued without touching the real session.
var proxyEnvExec = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), proxyEnvTimeout)
	defer cancel()

	return util.CommandContext(ctx, name, args...)
}

var sysProxyEnv struct {
	mu sync.Mutex
	// previous holds the values the session environment had before easyss
	// changed them. A key missing from the map was not set at all.
	previous map[string]string
	store    proxyEnvStore
}

// setSysProxyEnv publishes the proxy for the given local http proxy port to the
// session environment. It reports whether the environment was updated, which is
// false on a session that offers neither a systemd user manager nor a D-Bus
// session bus.
//
// Only applications started after this call inherit the new variables: a
// browser that is already running has to be restarted to pick the proxy up.
func setSysProxyEnv(port int) (bool, error) {
	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	if sysProxyEnv.store == proxyEnvStoreNone {
		sysProxyEnv.previous = snapshotSysProxyEnv()
	}

	store, err := applySysProxyEnv(sysProxyEnvValues(port))
	if store == proxyEnvStoreNone {
		return false, err
	}

	sysProxyEnv.store = store
	log.Info("[SYSPROXY] session environment updated, already running applications keep their previous proxy settings")
	return true, nil
}

// unsetSysProxyEnv restores the variables setSysProxyEnv overwrote. It reports
// whether it changed anything, which is false when this process never published
// a proxy.
func unsetSysProxyEnv() (bool, error) {
	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	if sysProxyEnv.store == proxyEnvStoreNone {
		return false, nil
	}

	// Keep the state when the restore fails, so that a retry -- the tray
	// reverts its checkmark and lets the user click again -- can still bring
	// the original values back.
	if err := restoreSysProxyEnv(sysProxyEnv.store, sysProxyEnv.previous); err != nil {
		return false, err
	}

	sysProxyEnv.previous = nil
	sysProxyEnv.store = proxyEnvStoreNone
	return true, nil
}

// sysProxyEnvValues returns the session environment easyss publishes for the
// given local http proxy port.
func sysProxyEnvValues(port int) map[string]string {
	addr := "http://127.0.0.1:" + strconv.Itoa(port)

	return map[string]string{
		"http_proxy":  addr,
		"https_proxy": addr,
		"no_proxy":    sysProxyNoProxy,
		"HTTP_PROXY":  addr,
		"HTTPS_PROXY": addr,
		"NO_PROXY":    sysProxyNoProxy,
	}
}

// snapshotSysProxyEnv records the proxy related variables the session
// environment currently holds, so that unsetSysProxyEnv can put them back. A
// variable missing from the result was not set before.
func snapshotSysProxyEnv() map[string]string {
	previous := make(map[string]string, len(sysProxyEnvKeys))

	current, err := systemdUserEnv()
	if err != nil {
		// Restoring then degrades to clearing the variables, which still beats
		// leaving a proxy pointing at a stopped easyss behind.
		log.Warn("[SYSPROXY] cannot read session environment, previous proxy values will not be restored", "err", err)
		return previous
	}

	for _, key := range sysProxyEnvKeys {
		if value, ok := current[key]; ok {
			previous[key] = value
		}
	}

	return previous
}

// applySysProxyEnv publishes the given values to the session environment.
//
// Exactly one store is used. The systemd user manager is preferred because it is
// what desktop sessions that launch applications through systemd -- uwsm on
// Hyprland, for instance -- hand down to them, and because it can remove a
// variable again. Only when there is no usable user manager does easyss fall
// back to the D-Bus activation environment.
//
// Writing to both would be a mistake: with dbus-broker the activation
// environment *is* the systemd user manager environment, so the values would be
// published twice and could no longer be removed cleanly.
func applySysProxyEnv(values map[string]string) (proxyEnvStore, error) {
	assignments := make([]string, 0, len(sysProxyEnvKeys))
	for _, key := range sysProxyEnvKeys {
		assignments = append(assignments, key+"="+values[key])
	}

	systemdErr := runProxyEnvCmd(proxyEnvCmd{"systemctl", append([]string{"--user", "set-environment"}, assignments...)})
	if systemdErr == nil {
		return proxyEnvStoreSystemd, nil
	}

	dbusErr := runProxyEnvCmd(proxyEnvCmd{"dbus-update-activation-environment", assignments})
	if dbusErr != nil {
		return proxyEnvStoreNone, errors.Join(systemdErr, dbusErr)
	}

	log.Warn("[SYSPROXY] systemd user manager not reachable, using the D-Bus activation environment", "err", systemdErr)
	return proxyEnvStoreDBus, nil
}

// restoreSysProxyEnv puts the session environment back to the values
// snapshotSysProxyEnv captured, using the store the proxy was published to.
func restoreSysProxyEnv(store proxyEnvStore, previous map[string]string) error {
	if store == proxyEnvStoreDBus {
		// dbus-daemon cannot remove a variable once it has been set, so the
		// ones easyss introduced are emptied instead: Chromium, curl and
		// friends treat an empty proxy variable the same as an unset one.
		assignments := make([]string, 0, len(sysProxyEnvKeys))
		for _, key := range sysProxyEnvKeys {
			assignments = append(assignments, key+"="+previous[key])
		}
		return runProxyEnvCmd(proxyEnvCmd{"dbus-update-activation-environment", assignments})
	}

	var systemdSet, systemdUnset []string
	for _, key := range sysProxyEnvKeys {
		if value, ok := previous[key]; ok {
			systemdSet = append(systemdSet, key+"="+value)
			continue
		}
		systemdUnset = append(systemdUnset, key)
	}

	// Putting the previous values back and removing the ones easyss added are
	// two independent commands, and both have to run.
	var errs []error
	if len(systemdSet) > 0 {
		cmd := proxyEnvCmd{"systemctl", append([]string{"--user", "set-environment"}, systemdSet...)}
		errs = append(errs, runProxyEnvCmd(cmd))
	}
	if len(systemdUnset) > 0 {
		cmd := proxyEnvCmd{"systemctl", append([]string{"--user", "unset-environment"}, systemdUnset...)}
		errs = append(errs, runProxyEnvCmd(cmd))
	}

	return errors.Join(errs...)
}

// runProxyEnvCmd runs one environment update command.
func runProxyEnvCmd(cmd proxyEnvCmd) error {
	_, err := proxyEnvExec(cmd.name, cmd.args...)
	return err
}

// systemdUserEnv reads the environment of the systemd user manager.
func systemdUserEnv() (map[string]string, error) {
	out, err := proxyEnvExec("systemctl", "--user", "show-environment")
	if err != nil {
		return nil, err
	}

	env := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			env[name] = value
		}
	}

	return env, nil
}
