package sysproxy

import (
	"errors"
	"testing"
)

// desktopStub 替代桌面代理设置的读写，测试不碰运行机器的真实系统代理。
type desktopStub struct {
	onHTTPErr, onHTTPSErr   error
	offHTTPErr, offHTTPSErr error

	offs int
}

func newDesktopState(t *testing.T, stub *desktopStub) *State {
	t.Helper()

	state := newTestState(t)
	state.desktop = desktopProxy{
		onHTTP:   func(string) error { return stub.onHTTPErr },
		onHTTPS:  func(string) error { return stub.onHTTPSErr },
		offHTTP:  func() error { stub.offs++; return stub.offHTTPErr },
		offHTTPS: func() error { stub.offs++; return stub.offHTTPSErr },
	}
	return state
}

// TestEnableCompensatesPartialDesktopSettings：调用方只在成功时记"已应用"，
// 只写了一半的代理必须在 Enable 内撤销，否则退出后它一直指向已停止的本地端口。
func TestEnableCompensatesPartialDesktopSettings(t *testing.T) {
	t.Parallel()

	stub := &desktopStub{onHTTPSErr: errors.New("registry locked")}
	state := newDesktopState(t, stub)

	err := state.Enable("127.0.0.1:5080")
	if err == nil {
		t.Fatal("Enable = nil, want the https failure")
	}
	if errors.Is(err, ErrResidual) {
		t.Fatalf("Enable = %v, want no residual after a successful revert", err)
	}
	if stub.offs != 2 {
		t.Fatalf("desktop reverts = %d, want both protocols reverted", stub.offs)
	}
}

func TestEnableReportsResidualWhenCompensationFails(t *testing.T) {
	t.Parallel()

	stub := &desktopStub{
		onHTTPSErr: errors.New("registry locked"),
		offHTTPErr: errors.New("registry still locked"),
	}
	state := newDesktopState(t, stub)

	err := state.Enable("127.0.0.1:5080")
	if !errors.Is(err, ErrResidual) {
		t.Fatalf("Enable = %v, want ErrResidual so the caller keeps the proxy applied", err)
	}
	if stub.offs != 2 {
		t.Fatalf("desktop reverts = %d, want an attempt for both protocols", stub.offs)
	}
}

// 两边都失败说明没改到系统代理，撤销只会破坏用户原有的代理设置。
func TestEnableDoesNotRevertWhenNothingWasWritten(t *testing.T) {
	t.Parallel()

	stub := &desktopStub{
		onHTTPErr:  errors.New("no registry"),
		onHTTPSErr: errors.New("no registry"),
	}
	state := newDesktopState(t, stub)

	err := state.Enable("127.0.0.1:5080")
	if err == nil {
		t.Fatal("Enable = nil, want an error")
	}
	if stub.offs != 0 {
		t.Fatalf("desktop reverts = %d, want none when nothing was written", stub.offs)
	}
}

func TestEnableKeepsDesktopSettingsOnSuccess(t *testing.T) {
	t.Parallel()

	stub := &desktopStub{}
	state := newDesktopState(t, stub)

	if err := state.Enable("127.0.0.1:5080"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if stub.offs != 0 {
		t.Fatalf("desktop reverts = %d, want none after a successful apply", stub.offs)
	}
}

func TestDisableRevertsBothDesktopProtocols(t *testing.T) {
	t.Parallel()

	stub := &desktopStub{}
	state := newDesktopState(t, stub)

	if err := state.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if stub.offs != 2 {
		t.Fatalf("desktop reverts = %d, want both protocols", stub.offs)
	}
}
