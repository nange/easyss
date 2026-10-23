//go:build !headless

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tray"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
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
	// 当前平台的 net 错误：Unix 是 EADDRINUSE，Windows 是 WSAEADDRINUSE。
	msg := friendlyStartupError(addrInUseTestErr())
	if !strings.Contains(msg, "本地端口可能被占用") {
		t.Fatalf("EADDRINUSE should get the port-in-use hint: %q", msg)
	}

	// 空密码（crypto.ErrPasswordEmpty）。
	passwordErr := fmt.Errorf("derive master key: %w", crypto.ErrPasswordEmpty)
	if msg := friendlyStartupError(passwordErr); !strings.Contains(msg, "服务器密码为空") {
		t.Fatalf("empty-password error should get the config hint: %q", msg)
	}

	// HTTP 代理未启用 socks_port（runner.ErrSocksRequired）。
	socksRequiredErr := fmt.Errorf("runner: %w", runner.ErrSocksRequired)
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

// vpnRefusalWarning 构造托盘实际会读到的那种启动警告：会话起点的门禁失败已经由
// runner.Run 包成"vpn disabled for this session"，并可能与被 errors.Join 起来的其它
// 警告并存（例如服务端域名尚未解析成功）。
func vpnRefusalWarning(others ...error) error {
	return errors.Join(append(others,
		fmt.Errorf("vpn disabled for this session: %w", clientconfig.ErrCurrentServerNotDERPRelay))...)
}

// TestStartupWarningNotice 固定"哪些启动警告值得打断用户"：只有 VPN 那条。
//
// 其余警告在切换服务器之后仍然只写日志——启动路径已经在弹它们，网络未就绪的恢复提示
// 另有 watchServerDomainReady 负责，重复弹窗只会变成噪音。
func TestStartupWarningNotice(t *testing.T) {
	if startupWarningNotice(nil) {
		t.Error("nil must not notify")
	}
	if startupWarningNotice(errors.New("load custom rule file: boom")) {
		t.Error("a generic startup warning must stay in the log")
	}
	if startupWarningNotice(fmt.Errorf("%w: proxy.example.com", runner.ErrServerDomainUnresolved)) {
		t.Error("the server-domain warning must stay in the log")
	}
	if !startupWarningNotice(vpnRefusalWarning()) {
		t.Error("the relay refusal must notify")
	}
	if !startupWarningNotice(vpnRefusalWarning(
		fmt.Errorf("%w: proxy.example.com", runner.ErrServerDomainUnresolved))) {
		t.Error("the relay refusal must notify even when other warnings are joined with it")
	}
}

// TestVPNRefusalText 固定通知文案：说清"VPN 功能不生效"、点名是哪台服务器、给出修法，
// 并保留原始错误作为详情（两条修法都在里面）。
func TestVPNRefusalText(t *testing.T) {
	err := vpnRefusalWarning()
	msg := vpnRefusalText("b.example.com:443", err)
	for _, want := range []string{
		"VPN 功能不生效",
		"b.example.com:443",
		"中继(DERP)列表",
		"\"derp\": true",
		"代理（SOCKS5/HTTP）仍可正常使用",
		err.Error(),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("notification %q is missing %q", msg, want)
		}
	}

	// 没有会话（或没有服务器条目）时也要能渲染：宁可少一句主语，也不能弹一条空通知。
	if msg := vpnRefusalText("", err); !strings.Contains(msg, "VPN 功能不生效") {
		t.Errorf("notification without a server name is unusable: %q", msg)
	}
}

// TestStartupWarningTextUsesTheRunningSessionServer 固定"文案说的是运行中会话实际
// 使用的那台服务器"这条契约，也就是本次修正的核心：判据与文案都不能跟着 App 快照的
// default 标记走——托盘切换、失败回滚与自更新重启都会替换那份快照，而正在跑的会话仍
// 停在它启动时选中的那台上。
func TestStartupWarningTextUsesTheRunningSessionServer(t *testing.T) {
	a := newSwitchTestApp(t) // 初始 default 是 a.example:443
	// 让 App 快照的 default 指向 b：会话还跑在 a 上（先发布下标、新会话还没起来的窗口，
	// 或一次回滚）。文案必须点名 a。
	a.updateConfig(func(c *clientconfig.ClientConfig) { c.SetDefaultServerIndex(1) })
	a.sess.installCore(&runner.Core{ServerAddr: "a.example:443"})

	msg := a.startupWarningText(vpnRefusalWarning())
	if !strings.Contains(msg, "a.example:443") {
		t.Errorf("notification %q must name the server the session is running on", msg)
	}
	if strings.Contains(msg, "b.example:443") {
		t.Errorf("notification %q must not name the App snapshot's default server", msg)
	}
	if !strings.Contains(msg, "VPN 功能不生效") {
		t.Errorf("notification %q must say the vpn is not in effect", msg)
	}
}

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
	ui := newStubAppUI()
	notified := ui.domainReady

	ready, done := make(chan struct{}), make(chan struct{})
	a := &App{ui: ui}
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
	a4 := &App{ui: newStubAppUI()}
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

	// 用户取消了 pkexec/osascript 授权对话框：提权器在 helper 启动前退出，
	// 这是用户意图而非故障，因此同样保持静默。
	cancelled := fmt.Errorf("%w: pkexec: exit status 126: Request dismissed", tunhelper.ErrStartup)
	if msg := friendlyTunError(cancelled); msg != "" {
		t.Fatalf("a cancelled auth dialog must not notify, got %q", msg)
	}
	osascript := fmt.Errorf("%w: osascript: exit status 1: User canceled", tunhelper.ErrStartup)
	if msg := friendlyTunError(osascript); msg != "" {
		t.Fatalf("a cancelled admin dialog must not notify, got %q", msg)
	}

	// 缺少权限时保留可操作的建议提示。
	perm := fmt.Errorf("tun: create device: open /dev/net/tun: %w", fs.ErrPermission)
	if msg := friendlyTunError(perm); !strings.Contains(msg, "需要管理员权限") {
		t.Fatalf("an fs.ErrPermission failure should get the elevation hint: %q", msg)
	}

	// 创建脚本失败（非权限原因）走 typed sentinel，文案说明已回滚。
	createErr := fmt.Errorf("%w: exit status 1", tun.ErrCreateDevice)
	if msg := friendlyTunError(createErr); !strings.Contains(msg, "已回滚") {
		t.Fatalf("a create-device failure should get the rollback hint: %q", msg)
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

// TestTrayTunStartFailureUnchecksTheMenu 守住失败后菜单必须回到未勾选：引擎没在跑，
// 勾着会让用户以为它在跑。会话拆除由 session.rollbackFailedTunStart 负责，不在此用例范围。
func TestTrayTunStartFailureUnchecksTheMenu(t *testing.T) {
	a := &trayApp{App: New(&clientconfig.ClientConfig{}, ""), shell: tray.NewShell()}

	a.object = tray.NewObjectMenu(systray.NewMenu(), &clientconfig.ClientConfig{}, func() {}, func() {})
	a.object.SetTunChecked(true)

	a.tunStartFailed(fmt.Errorf("%w: boom", tun.ErrCreateDevice))
	require.False(t, a.object.TunChecked(), "失败后菜单必须回到未勾选")

	// 主动停止（context.Canceled）：同样回滚勾选，但不打扰用户（消息为空）。
	a.object.SetTunChecked(true)
	a.tunStartFailed(fmt.Errorf("tun: start engine: %w", context.Canceled))
	require.False(t, a.object.TunChecked(), "被主动取消的启动同样必须回滚菜单")
}

// TestTunStartFailureTextIsEmptyForUserCancelledStarts 固化"不打扰用户"的判定：
// 用户主动造成的失败（停止、关闭开关、取消授权）不产生任何面向用户的消息，
// 其余失败必须带上下文。
func TestTunStartFailureTextIsEmptyForUserCancelledStarts(t *testing.T) {
	if msg := friendlyTunError(context.Canceled); msg != "" {
		t.Fatalf("a cancelled start must not produce a message, got %q", msg)
	}
	msg := friendlyTunError(fmt.Errorf("%w: boom", tun.ErrCreateDevice))
	if !strings.Contains(msg, "Tun2socks 启动失败") {
		t.Fatalf("a real failure must produce a message, got %q", msg)
	}
}
