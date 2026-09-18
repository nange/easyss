//go:build !headless

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nange/easyss/v3/runner"
)

func TestFriendlyConfigError(t *testing.T) {
	var v any
	err := json.Unmarshal([]byte(`{"servers": [`), &v)
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Fatalf("expected *json.SyntaxError, got %T", err)
	}
	if got := friendlyConfigError(syntaxErr); got != "JSON配置文件解析失败："+syntaxErr.Error() {
		t.Fatalf("unexpected JSON error message: %q", got)
	}

	var mm map[string]int
	err = json.Unmarshal([]byte(`{"timeout": "abc"}`), &mm)
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("expected *json.UnmarshalTypeError, got %T", err)
	}
	if got := friendlyConfigError(typeErr); got != "JSON配置文件解析失败："+typeErr.Error() {
		t.Fatalf("unexpected JSON type error message: %q", got)
	}

	if got := friendlyConfigError(fs.ErrNotExist); got != "配置文件不存在："+fs.ErrNotExist.Error() {
		t.Fatalf("unexpected not-exist message: %q", got)
	}

	if got := friendlyConfigError(errors.New("server is required")); got != "配置文件加载失败：server is required" {
		t.Fatalf("unexpected generic message: %q", got)
	}
}

func TestFriendlyStartupError(t *testing.T) {
	// Unix：基于 errno 的检测。
	msg := friendlyStartupError(syscall.EADDRINUSE)
	if !strings.Contains(msg, "本地端口可能被占用") {
		t.Fatalf("EADDRINUSE should get the port-in-use hint: %q", msg)
	}

	// Windows：标准的错误消息文本。
	windowsErr := errors.New("bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if msg := friendlyStartupError(windowsErr); !strings.Contains(msg, "本地端口可能被占用") {
		t.Fatalf("windows in-use error should get the hint: %q", msg)
	}

	// 空密码（crypto.DeriveMasterKey）。
	passwordErr := errors.New("crypto: password is empty")
	if msg := friendlyStartupError(passwordErr); !strings.Contains(msg, "服务器密码为空") {
		t.Fatalf("empty-password error should get the config hint: %q", msg)
	}

	// HTTP 代理未启用 socks_port（runner.errSocksRequired）。
	socksRequiredErr := errors.New("http proxy requires socks_port to be enabled")
	if msg := friendlyStartupError(socksRequiredErr); !strings.Contains(msg, "socks_port 需大于 0") {
		t.Fatalf("socks-required error should get the config hint: %q", msg)
	}

	other := errors.New("boom")
	if msg := friendlyStartupError(other); msg != "服务启动失败：boom" {
		t.Fatalf("unexpected generic startup message: %q", msg)
	}
}

func TestFriendlyStartupWarning(t *testing.T) {
	// 非致命的启动警告（例如自定义规则文件加载失败）保留 "启动警告" 前缀和详情。
	msg := friendlyStartupWarning(errors.New("load custom rule file: open direct.txt: no such file or directory"))
	if msg != "启动警告：load custom rule file: open direct.txt: no such file or directory" {
		t.Fatalf("unexpected startup warning message: %q", msg)
	}

	// 服务端域名解析失败（runner.ErrServerDomainUnresolved）单独给出
	// "网络可能尚未就绪、已在后台重试" 的说明，且 errors.Join 包装后仍能识别。
	resolveErr := errors.Join(
		errors.New("load custom rule file: boom"),
		fmt.Errorf("%w: proxy.example.com: %v", runner.ErrServerDomainUnresolved, errors.New("dns boom")),
	)
	msg = friendlyStartupWarning(resolveErr)
	for _, want := range []string{"启动警告", "网络尚未就绪", "后台自动重试", resolveErr.Error()} {
		if !strings.Contains(msg, want) {
			t.Fatalf("server-domain warning %q is missing %q", msg, want)
		}
	}
}

// fakeDomainReadiness 是 serverDomainReadiness 的测试替身：cmd 包内无法构造
// 带可用通道的 *runner.Core（字段不可导出）。
type fakeDomainReadiness struct {
	ready <-chan struct{}
	done  <-chan struct{}
}

func (f fakeDomainReadiness) ServerDomainReady() <-chan struct{} { return f.ready }
func (f fakeDomainReadiness) Done() <-chan struct{}              { return f.done }

func TestCanStartTunNow(t *testing.T) {
	if !canStartTunNow(nil) {
		t.Fatal("nil core must be treated as ready")
	}
	if !canStartTunNow(fakeDomainReadiness{}) {
		t.Fatal("an uninitialized ready channel must be treated as ready")
	}

	open := make(chan struct{})
	if canStartTunNow(fakeDomainReadiness{ready: open}) {
		t.Fatal("an open ready channel must defer the TUN start")
	}
	close(open)
	if !canStartTunNow(fakeDomainReadiness{ready: open}) {
		t.Fatal("a closed ready channel must allow the TUN start")
	}
}

func TestWatchServerDomainReady(t *testing.T) {
	orig := serverDomainReadyNotify
	t.Cleanup(func() { serverDomainReadyNotify = orig })

	notified := make(chan string, 4)
	serverDomainReadyNotify = func(msg string) { notified <- msg }

	ready, done := make(chan struct{}), make(chan struct{})
	a := &App{}
	gen := coreGen.Add(1)
	a.watchServerDomainReady(fakeDomainReadiness{ready: ready, done: done}, gen, true, true)

	select {
	case msg := <-notified:
		t.Fatalf("notified before the domain became ready: %q", msg)
	case <-time.After(50 * time.Millisecond):
	}

	close(ready)
	select {
	case msg := <-notified:
		// TUN 被跳过时，恢复通知要额外提醒如何重新开启全局流量。
		for _, want := range []string{"已就绪", "重新开启"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("unexpected recovery notification %q, missing %q", msg, want)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notification after the domain became ready")
	}

	// 启动即就绪（pending=false）不派发通知。
	ready2, done2 := make(chan struct{}), make(chan struct{})
	close(ready2)
	a.watchServerDomainReady(fakeDomainReadiness{ready: ready2, done: done2}, coreGen.Add(1), false, false)
	select {
	case msg := <-notified:
		t.Fatalf("a non-degraded start must not notify on recovery: %q", msg)
	case <-time.After(50 * time.Millisecond):
	}

	// 核心被替换（序号更新）后，过期核心不再弹通知。
	ready3, done3 := make(chan struct{}), make(chan struct{})
	a.watchServerDomainReady(fakeDomainReadiness{ready: ready3, done: done3}, coreGen.Add(1), true, false)
	coreGen.Add(1) // 模拟下一次 App.Start
	close(ready3)
	select {
	case msg := <-notified:
		t.Fatalf("a stale core must not notify: %q", msg)
	case <-time.After(50 * time.Millisecond):
	}

	// 核心已停止：就绪信号到达也不通知（TUN 被跳过的提示走同一通道）。
	ready4, done4 := make(chan struct{}), make(chan struct{})
	a4 := &App{}
	a4.watchServerDomainReady(fakeDomainReadiness{ready: ready4, done: done4}, coreGen.Add(1), true, true)
	close(done4)
	close(ready4)
	select {
	case msg := <-notified:
		t.Fatalf("a stopped core must not notify: %q", msg)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestFriendlyTunError(t *testing.T) {
	// 由 Stop() 取消的启动（关闭开关、切换服务器、退出应用）不算失败：
	// 不得显示任何内容，否则每次关闭 TUN 都会弹出一条通知。
	if msg := friendlyTunError(context.Canceled); msg != "" {
		t.Fatalf("context.Canceled must not notify, got %q", msg)
	}
	if msg := friendlyTunError(fmt.Errorf("tun: start engine: %w", context.Canceled)); msg != "" {
		t.Fatalf("a wrapped context.Canceled must not notify, got %q", msg)
	}
	if msg := friendlyTunError(nil); msg != "" {
		t.Fatalf("nil error must not notify, got %q", msg)
	}

	// 用户取消了 pkexec/osascript 授权对话框：平台包装层会发出这些固定
	// 字面量，这是用户意图而非故障，因此同样保持静默。
	cancelled := errors.New("pkexec exited before tun helper started: exit status 126: Error executing command as another user: Request dismissed")
	if msg := friendlyTunError(cancelled); msg != "" {
		t.Fatalf("a cancelled auth dialog must not notify, got %q", msg)
	}
	osascript := errors.New("osascript exited before tun helper started: exit status 1: User canceled.")
	if msg := friendlyTunError(osascript); msg != "" {
		t.Fatalf("a cancelled admin dialog must not notify, got %q", msg)
	}

	// 缺少权限时保留可操作的建议提示。
	denied := errors.New("tun2socks requires root on this platform")
	if msg := friendlyTunError(denied); !strings.Contains(msg, "需要管理员权限") || !strings.Contains(msg, denied.Error()) {
		t.Fatalf("a permission failure should get the elevation hint: %q", msg)
	}
	perm := fmt.Errorf("tun: create device: open /dev/net/tun: %w", fs.ErrPermission)
	if msg := friendlyTunError(perm); !strings.Contains(msg, "需要管理员权限") {
		t.Fatalf("an fs.ErrPermission failure should get the elevation hint: %q", msg)
	}

	// 其他任何错误都会同时说明缺失的功能、代理核心仍然可用的事实，
	// 以及底层原因。
	engineErr := errors.New("tun: start engine: boom")
	msg := friendlyTunError(engineErr)
	for _, want := range []string{"Tun2socks 启动失败", "系统全局流量未生效", "代理（SOCKS5/HTTP）仍可正常使用", engineErr.Error()} {
		if !strings.Contains(msg, want) {
			t.Fatalf("generic TUN message %q is missing %q", msg, want)
		}
	}
}

func TestTrayStartTunFailureNotifies(t *testing.T) {
	origHook, origNotify, origText := tunStartFailureHook, tunStartNotify, tunStartErrorText
	t.Cleanup(func() {
		tunStartFailureHook, tunStartNotify, tunStartErrorText = origHook, origNotify, origText
	})

	var (
		reverted  int
		notified  []string
		notifyMu  sync.Mutex
		tunFailed = errors.New("tun: create device: boom")
	)
	tunStartFailureHook = func() { reverted++ }
	tunStartNotify = func(msg string) {
		notifyMu.Lock()
		defer notifyMu.Unlock()
		notified = append(notified, msg)
	}
	tunStartErrorText = friendlyTunError

	trayStartTunFailure(tunFailed)

	notifyMu.Lock()
	got := append([]string(nil), notified...)
	notifyMu.Unlock()
	if reverted != 1 {
		t.Fatalf("revert hook calls = %d, want 1", reverted)
	}
	if len(got) != 1 {
		t.Fatalf("notifications = %q, want exactly one", got)
	}
	if !strings.Contains(got[0], tunFailed.Error()) {
		t.Fatalf("notification %q should carry the underlying reason", got[0])
	}

	// 主动停止仍然必须回滚状态（关闭开关的路径依赖于此），但不得通知。
	trayStartTunFailure(fmt.Errorf("tun: start engine: %w", context.Canceled))

	notifyMu.Lock()
	defer notifyMu.Unlock()
	if reverted != 2 {
		t.Fatalf("revert hook calls after a cancelled start = %d, want 2", reverted)
	}
	if len(notified) != 1 {
		t.Fatalf("a cancelled start notified %q, want no extra notification", notified[1:])
	}
}

// TestTrayStartTunFailureHeadlessText 固化无 tray.go 构建中 main.go 保留的
// 回退行为：未安装 tunStartErrorText 时，通知的将是原始错误文本。
func TestTrayStartTunFailureHeadlessText(t *testing.T) {
	origHook, origNotify, origText := tunStartFailureHook, tunStartNotify, tunStartErrorText
	t.Cleanup(func() {
		tunStartFailureHook, tunStartNotify, tunStartErrorText = origHook, origNotify, origText
	})

	raw := errors.New("tun: create device: boom")
	var notified []string
	tunStartFailureHook = nil
	tunStartNotify = func(msg string) { notified = append(notified, msg) }
	tunStartErrorText = nil

	trayStartTunFailure(raw)

	if len(notified) != 1 || notified[0] != raw.Error() {
		t.Fatalf("headless fallback notified %q, want [%q]", notified, raw.Error())
	}
}
