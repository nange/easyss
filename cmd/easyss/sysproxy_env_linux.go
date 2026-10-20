//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

const (
	// sysProxyNoProxy 让发往本机自身的流量不经过代理，否则对本地 HTTP 入口 /stats 的请求
	// 会被送进监听在同一地址的代理。
	sysProxyNoProxy = "localhost,127.0.0.1,::1"

	// proxyEnvTimeout 限制外部命令的执行时间，无响应的会话总线不会阻塞启动或托盘。
	proxyEnvTimeout = 5 * time.Second
)

// sysProxyEnvKeys 列出 easyss 发布并恢复的所有变量。Chromium 在 GNOME 上读 gsettings、
// KDE 上读 kioslaverc，在其他桌面（Hyprland、sway 等）上忽略系统设置、只看这些环境变量。
var sysProxyEnvKeys = []string{
	"http_proxy", "https_proxy", "no_proxy",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
}

type proxyEnvStore int

const (
	proxyEnvStoreNone proxyEnvStore = iota
	proxyEnvStoreSystemd
	proxyEnvStoreDBus
)

type proxyEnvCmd struct {
	name string
	args []string
}

type proxyEnvState struct {
	mu sync.Mutex
	// previous 保存 easyss 修改会话环境前的值，缺失的键表示该变量未被设置过。
	previous map[string]string
	store    proxyEnvStore
	// exec 为 nil 时用生产实现；测试注入确定性的命令结果。
	exec func(name string, args ...string) (string, error)
}

var sysProxyEnv proxyEnvState

func (e *proxyEnvState) run(name string, args ...string) (string, error) {
	if e.exec != nil {
		return e.exec(name, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), proxyEnvTimeout)
	defer cancel()

	return util.CommandContext(ctx, name, args...)
}

// setSysProxyEnv 把本地 HTTP 代理发布到会话环境，addr 由调用方按 bind_all 选好同族回环。只有
// 之后启动的应用才会继承变量，已在运行的浏览器必须重启。无 systemd/D-Bus 时返回 false。
func setSysProxyEnv(addr string) (bool, error) {
	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	if sysProxyEnv.store == proxyEnvStoreNone {
		sysProxyEnv.previous = snapshotSysProxyEnv()
	}

	store, err := applySysProxyEnv(sysProxyEnvValues(addr))
	if store == proxyEnvStoreNone {
		return false, err
	}

	sysProxyEnv.store = store
	log.Info("[SYSPROXY] session environment updated, already running applications keep their previous proxy settings")
	return true, nil
}

// unsetSysProxyEnv 恢复 setSysProxyEnv 覆盖的变量；本进程从未发布过代理时返回 false。
func unsetSysProxyEnv() (bool, error) {
	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	if sysProxyEnv.store == proxyEnvStoreNone {
		return false, nil
	}

	// 恢复失败时保留状态，这样重试（托盘回滚勾选并让用户再点一次）仍能恢复原始值。
	if err := restoreSysProxyEnv(sysProxyEnv.store, sysProxyEnv.previous); err != nil {
		return false, err
	}

	sysProxyEnv.previous = nil
	sysProxyEnv.store = proxyEnvStoreNone
	return true, nil
}

// sysProxyEnvValues 返回 easyss 为给定本地 HTTP 代理地址发布的会话环境。地址不带 scheme，
// 由这里补上。
func sysProxyEnvValues(addr string) map[string]string {
	proxyURL := "http://" + addr

	return map[string]string{
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"no_proxy":    sysProxyNoProxy,
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"NO_PROXY":    sysProxyNoProxy,
	}
}

// snapshotSysProxyEnv 记录会话环境当前的代理相关变量，供 unsetSysProxyEnv 恢复。
func snapshotSysProxyEnv() map[string]string {
	previous := make(map[string]string, len(sysProxyEnvKeys))

	current, err := systemdUserEnv()
	if err != nil {
		// 恢复降级为清除这些变量，仍好过留下一个指向已停止 easyss 的代理配置。
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

// applySysProxyEnv 只用一个存储：优先 systemd 用户管理器，没有时才回退到 D-Bus activation。
// 同时写入两者是错的：用 dbus-broker 时 activation 环境就是 systemd 环境，值无法干净移除。
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

// restoreSysProxyEnv 用发布代理时所用的存储，把会话环境恢复到 snapshotSysProxyEnv 的值。
func restoreSysProxyEnv(store proxyEnvStore, previous map[string]string) error {
	if store == proxyEnvStoreDBus {
		// dbus-daemon 一旦设置了变量就无法再删除，因此改为清空 easyss 引入的变量：
		// Chromium、curl 等把空的代理变量视同未设置。
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

	// 恢复先前的值与移除 easyss 添加的值是两个独立命令，两者都必须执行。
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

func runProxyEnvCmd(cmd proxyEnvCmd) error {
	_, err := sysProxyEnv.run(cmd.name, cmd.args...)
	return err
}

func systemdUserEnv() (map[string]string, error) {
	out, err := sysProxyEnv.run("systemctl", "--user", "show-environment")
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
