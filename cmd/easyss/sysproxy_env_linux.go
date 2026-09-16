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
	// sysProxyNoProxy 让发往本机自身的流量不经过代理。
	// 没有它，对 http://127.0.0.1:<http_port>/stats 的请求
	// 会被发送到监听在同一地址的代理上。
	sysProxyNoProxy = "localhost,127.0.0.1,::1"

	// proxyEnvTimeout 限制下面外部命令的执行时间，
	// 这样无响应的会话总线不会阻塞启动或托盘。
	proxyEnvTimeout = 5 * time.Second
)

// sysProxyEnvKeys 列出 easyss 发布并恢复的所有变量。
//
// 程序根据它们检测到的桌面环境来选择代理来源：
// Chromium 在 GNOME 上读取 gsettings，在 KDE 上读取 kioslaverc，
// 但在任何其他桌面（Hyprland、sway 等）上它会完全忽略系统设置，
// 只看这些环境变量。因此把它们发布到会话环境，
// 就填补了纯 Hyprland 会话中的浏览器直连互联网的缺口。
var sysProxyEnvKeys = []string{
	"http_proxy", "https_proxy", "no_proxy",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
}

// proxyEnvStore 标识 setSysProxyEnv 把代理发布到了哪里。
type proxyEnvStore int

const (
	proxyEnvStoreNone proxyEnvStore = iota
	proxyEnvStoreSystemd
	proxyEnvStoreDBus
)

// proxyEnvCmd 是读取或更新会话环境的单个外部命令。
type proxyEnvCmd struct {
	name string
	args []string
}

// proxyEnvExec 运行这样的命令。它是变量，以便测试可以观察
// 发出的命令而无需触碰真实会话。
var proxyEnvExec = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), proxyEnvTimeout)
	defer cancel()

	return util.CommandContext(ctx, name, args...)
}

var sysProxyEnv struct {
	mu sync.Mutex
	// previous 保存 easyss 修改会话环境之前的值。
	// 映射中缺失的键表示原本根本没有设置。
	previous map[string]string
	store    proxyEnvStore
}

// setSysProxyEnv 把给定本地 HTTP 代理端口的代理配置发布到会话环境。
// 它报告环境是否已更新；在没有 systemd 用户管理器也没有 D-Bus
// 会话总线的会话上返回 false。
//
// 只有此调用之后启动的应用才会继承新变量：
// 已在运行的浏览器必须重启才能使用该代理。
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

// unsetSysProxyEnv 恢复 setSysProxyEnv 覆盖的变量。它报告是否
// 改变了什么；当本进程从未发布过代理时返回 false。
func unsetSysProxyEnv() (bool, error) {
	sysProxyEnv.mu.Lock()
	defer sysProxyEnv.mu.Unlock()

	if sysProxyEnv.store == proxyEnvStoreNone {
		return false, nil
	}

	// 恢复失败时保留状态，这样重试 —— 托盘回滚勾选并允许用户再次点击 ——
	// 仍能把原始值恢复回来。
	if err := restoreSysProxyEnv(sysProxyEnv.store, sysProxyEnv.previous); err != nil {
		return false, err
	}

	sysProxyEnv.previous = nil
	sysProxyEnv.store = proxyEnvStoreNone
	return true, nil
}

// sysProxyEnvValues 返回 easyss 为给定本地 HTTP 代理端口发布的会话环境。
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

// snapshotSysProxyEnv 记录会话环境当前持有的代理相关变量，
// 以便 unsetSysProxyEnv 能恢复它们。结果中缺失的变量表示之前未设置。
func snapshotSysProxyEnv() map[string]string {
	previous := make(map[string]string, len(sysProxyEnvKeys))

	current, err := systemdUserEnv()
	if err != nil {
		// 此时恢复降级为清除这些变量，这仍然好过
		// 留下一个指向已停止 easyss 的代理配置。
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

// applySysProxyEnv 把给定值发布到会话环境。
//
// 只使用一个存储。优先使用 systemd 用户管理器，因为通过 systemd 启动应用的
// 桌面会话（例如 Hyprland 上的 uwsm）会把它传给应用，而且它能再次删除变量。
// 只有在没有可用的用户管理器时，easyss 才回退到 D-Bus activation 环境。
//
// 同时写入两者是错误的：使用 dbus-broker 时，activation 环境
// *就是* systemd 用户管理器环境，值会被发布两次，且无法再被干净地移除。
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

// restoreSysProxyEnv 使用发布代理时所用的存储，把会话环境恢复到
// snapshotSysProxyEnv 捕获的值。
func restoreSysProxyEnv(store proxyEnvStore, previous map[string]string) error {
	if store == proxyEnvStoreDBus {
		// dbus-daemon 一旦设置了变量就无法再删除，因此改为清空 easyss 引入的
		// 变量：Chromium、curl 等会把空的代理变量视同未设置。
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

	// 恢复先前的值和移除 easyss 添加的值是两个独立命令，两者都必须执行。
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

// runProxyEnvCmd 运行一条环境更新命令。
func runProxyEnvCmd(cmd proxyEnvCmd) error {
	_, err := proxyEnvExec(cmd.name, cmd.args...)
	return err
}

// systemdUserEnv 读取 systemd 用户管理器的环境。
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
