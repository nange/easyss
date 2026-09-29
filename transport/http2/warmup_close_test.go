package http2

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/transport"
	utls "github.com/refraction-networking/utls"
)

// warmUpCloseBudget 是"Close 之后预热必须立刻收手"的预算。它必须明显小于
// config.ProbeTimeout（3s）：没有生命周期绑定时，探测只会被自己的超时放开，
// 因此只有把预算压到它以下，测试才能区分"被 Close 中止"与"超时后自然结束"。
const warmUpCloseBudget = time.Second

// newWarmUpTestTransport 构造一个不连接任何真实服务器的传输层：拨号由
// dial 提供，ProbeToken 非空使探测函数被装配（否则 WarmUp 会以
// "probe not configured" 提前返回，测不到生命周期绑定）。
func newWarmUpTestTransport(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) transport.Transport {
	t.Helper()

	tr, err := New(Config{
		ServerURL:  "https://127.0.0.1:1",
		TLSConfig:  &utls.Config{InsecureSkipVerify: true},
		Timeout:    time.Second,
		ProbeToken: "test-probe-token",
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr
}

// TestWarmUpRejectedAfterClose 固定"已关闭的传输层不接受预热"：与 Open 一致，
// WarmUp 必须先检查传输层自身的状态，绝不能在一个已拆除的传输层上激活槽位、
// 重新拨号并下载探测载荷。
func TestWarmUpRejectedAfterClose(t *testing.T) {
	var dials atomic.Int64
	tr := newWarmUpTestTransport(t, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dial must not happen after Close")
	})

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := tr.WarmUp(context.Background()); err == nil {
		t.Fatal("WarmUp after Close returned nil, want the closed error")
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("WarmUp after Close dialed %d times, want 0", got)
	}
}

// TestWarmUpAbortsOnClose 固定"进行中的预热会被 Close 中止"。
//
// 预热是在后台 goroutine 中派发的（runner.dispatchWarmUp），核心停止时只能取消
// 那个 goroutine 的延迟等待，取消不到已经在飞的探测——因此探测必须绑定到传输层
// 自身的生命周期（t.ctx）。旧形态下这里的拨号会一直阻塞到探测超时，也就是说
// 用户停止核心之后，客户端仍会向服务端发起新的 TCP+TLS 连接并下载探测载荷。
func TestWarmUpAbortsOnClose(t *testing.T) {
	dialStarted := make(chan struct{}, 1)
	tr := newWarmUpTestTransport(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case dialStarted <- struct{}{}:
		default:
		}
		// 阻塞到探测上下文被取消：只有 Close 取消 t.ctx 才能解开。
		<-ctx.Done()
		return nil, ctx.Err()
	})

	warmUpDone := make(chan error, 1)
	go func() { warmUpDone <- tr.WarmUp(context.Background()) }()

	select {
	case <-dialStarted:
	case <-time.After(warmUpCloseBudget):
		t.Fatal("warm-up never started dialing")
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-warmUpDone:
	case <-time.After(warmUpCloseBudget):
		t.Fatal("WarmUp kept running after Close (probe outlived the transport)")
	}
}
