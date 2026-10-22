//go:build darwin || linux

package tunhelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/client/tun/scripts"
	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/unix"
)

type fifoOpenResult struct {
	f   *os.File
	err error
}

// 对 FIFO 的 open(2) 会阻塞到出现读取方，而读取方是通过 stdin 重定向启动的提权 helper，
// 因此必须异步。
func openFifoForWriteAsync(fifoPath string) <-chan fifoOpenResult {
	ch := make(chan fifoOpenResult, 1)
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		ch <- fifoOpenResult{f: f, err: err}
	}()
	return ch
}

// 放弃等待的调用方必须调用它：删除 FIFO 解不开已在等读取方的 open(2)，那个 goroutine 连同
// fd 会泄漏整个进程；打开读端（非阻塞）才能让挂起的 open 完成。
func releaseFifoOpen(fifoPath string, ch <-chan fifoOpenResult) {
	rd, err := os.OpenFile(fifoPath, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	select {
	case r := <-ch:
		if r.f != nil {
			_ = r.f.Close()
		}
	case <-time.After(time.Second):
	}
	_ = rd.Close()
}

// helper 装路由前取得它，直到清理完成退出才释放；内核在进程退出（含 kill -9）时释放 flock，
// 因此"能否立刻拿到这把锁"就是"helper 是否还在"。
const tunControlLockPath = "/tmp/easyss-tun.lock"

const (
	// 删除路由是幂等的，而残留一条分流默认路由就会让全机 IPv4 流量黑洞。
	tunCleanupAttempts   = 3
	tunCleanupRetryDelay = 300 * time.Millisecond
)

// 长期运行的提权 helper 入口：stdin 读到 EOF（主进程关闭 FIFO 或崩溃）即清理并退出。
func runTunHelper(httpAddr, fdSocketPath, logFilePath, logLevel string) int {
	if httpAddr == "" || fdSocketPath == "" {
		fmt.Fprintf(os.Stderr, "[TUN-HELPER] missing required flags\n")
		return 1
	}

	// 父进程阻塞在 ReceiveFd 等 helper 连套接字；在能发送 fd 之前就放弃的 helper 必须自己敲它，
	// 否则父进程要空等到 30 秒 accept 超时。
	h := &tunHelper{fd: -1}
	defer func() {
		if !h.fdSent {
			notifyStartFailure(fdSocketPath, h.failure)
		}
	}()

	// 尽早初始化日志器，错误才会进日志文件，而不是经由 stderr 丢到 /dev/null。
	log.Init(log.Config{FilePath: logFilePath, Level: logLevel})

	step, err := h.setup(httpAddr)
	if err != nil {
		return h.fail(step, err)
	}
	defer h.cleanup()

	if err := h.configure(); err != nil {
		return h.fail("run create script", err)
	}
	if err := h.sendFD(fdSocketPath); err != nil {
		return h.fail("send fd to parent", err)
	}

	h.keepAlive()
	return 0
}

// tunScript 是一次平台脚本执行：写临时文件、注入内核实际分配的设备名、执行并清理。
type tunScript struct {
	kind     string
	filename string
	content  []byte
	render   func(tun.ScriptArgs) []string
	// execPrefix 非空时给执行错误加前缀：create 的失败由调用方命名，close 需要自带上下文。
	execPrefix string
}

// 创建脚本是 fd 路径上唯一能写设备 MTU 的地方（第 9 个位置参数），实参由 tun.ScriptArgs 统一渲染。
func runCreateScript(device string, args tun.ScriptArgs) error {
	return tunScript{
		kind:     "create",
		filename: scripts.CreateTunFilename,
		content:  scripts.CreateTunBytes,
		render:   tun.ScriptArgs.Create,
	}.run(device, args)
}

// 关闭脚本按路由是否真的清掉给出退出码，调用方据此决定是否回滚；残留的分流路由会让停止 TUN 后断网。
func runCloseScript(device string, args tun.ScriptArgs) error {
	return tunScript{
		kind:       "close",
		filename:   scripts.CloseTunFilename,
		content:    scripts.CloseTunBytes,
		render:     tun.ScriptArgs.Close,
		execPrefix: "close script",
	}.run(device, args)
}

func (s tunScript) run(device string, args tun.ScriptArgs) error {
	if s.content == nil {
		return fmt.Errorf("no %s script for %s", s.kind, runtime.GOOS)
	}

	namePath, err := tun.WriteScriptToTemp(s.filename, s.content)
	if err != nil {
		return fmt.Errorf("write %s script: %w", s.kind, err)
	}
	defer os.Remove(namePath) //nolint:errcheck

	// 以调用方传入的为准：helper 拿到的是内核实际分配的名字，配置里那个只是请求名。
	args.Dev.Device = device
	if err := execScriptWithOutput(tunScriptShell, namePath, s.render(args)...); err != nil {
		if s.execPrefix != "" {
			return fmt.Errorf("%s: %w", s.execPrefix, err)
		}
		return err
	}
	return nil
}

// TunMask 必须带上，否则同一次会话在 fd 路径装出 /32、直连路径装出 /16，两者都能上网，偏差不会
// 报错。DNS 位刻意留空：脚本第 8 位要的是解析器 IP，而 DNSAddr 是 TUN resolver 的监听地址。
func scriptArgsFor(cfg *proxy.TunConfig) tun.ScriptArgs {
	return tun.NewScriptArgs(tun.DeviceConfig{
		Device:         cfg.Device,
		TunIP:          cfg.TunIP,
		TunGW:          cfg.TunGW,
		TunMask:        cfg.TunMask,
		TunIPV6Sub:     cfg.TunIPV6Sub,
		TunGWV6:        cfg.TunGWV6,
		ServerIPV6:     cfg.ServerIPV6,
		LocalGateway:   cfg.LocalGateway,
		LocalGatewayV6: cfg.LocalGatewayV6,
	}, "", cfg.MTU)
}

// 删除路由是幂等的，没清掉就重试。返回的错误绝不能改变退出码：父进程把非零退出码理解为
// "提权/启动失败"。
func cleanupTunRoutes(ops ops, device string, cfg *proxy.TunConfig) error {
	var lastErr error

	for attempt := 1; attempt <= tunCleanupAttempts; attempt++ {
		scriptErr := runCloseScript(device, scriptArgsFor(cfg))
		if scriptErr != nil {
			log.Warn("[TUN-HELPER] close script", "device", device, "attempt", attempt, "err", scriptErr)
		}

		removeLeftoverDevice(device)

		detail, leftover := ops.probe(device, cfg.TunGW)
		if !leftover {
			return nil
		}

		// 以残留为主错误，同时保留关闭脚本的失败原因——它通常就是根因。
		lastErr = errors.Join(scriptErr, fmt.Errorf("TUN routes still present after cleanup: %s", detail))

		if attempt < tunCleanupAttempts {
			time.Sleep(tunCleanupRetryDelay)
		}
	}

	return lastErr
}

// create 脚本把 1.1.1.1 所在的网段路由进 TUN，探测地址与脚本漂移会让 keep-alive 永远报告失败。
var tunRouteProbes = []string{"1.1.1.1"}

// TUN 路由就位时，被覆盖的地址会解析到 TUN 设备而绝不走物理默认路由。
func probeRoutedViaDevice(probe []string, cmd func(string) (string, error), marker string) (string, error) {
	var (
		out      string
		err      error
		lastAddr string
	)
	for _, addr := range probe {
		out, err = cmd(addr)
		if err == nil && strings.Contains(out, marker) {
			return out, nil
		}
		lastAddr = addr
	}
	if err == nil {
		err = fmt.Errorf("no probe resolved via %q (last %s)", marker, lastAddr)
	}
	return out, err
}

// 按空白分词后整体比较，不用子串匹配：否则 "dev tun" 会命中 "dev tun0"，误判成残留要付
// 一次多余的提权回滚。
func routeFieldsContain(out, key, value string) bool {
	fields := strings.Fields(out)
	for i, field := range fields {
		if field == key && i+1 < len(fields) && fields[i+1] == value {
			return true
		}
	}
	return false
}

// 带退避重试最长约 10 秒，防 HTTP 服务器尚未就绪。
func fetchTunConfig(httpAddr string) (*proxy.TunConfig, error) {
	url := fmt.Sprintf("http://%s/tun", httpAddr)

	var lastErr error
	for i := range 10 {
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
		}

		resp, err := http.Get(url) //nolint:gosec
		if err != nil {
			lastErr = err
			continue
		}
		// 每次迭代都关闭 body：改用 defer 的话，之前十次响应的 body 会一直开到函数返回。
		if resp.StatusCode == http.StatusServiceUnavailable {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("tun not configured yet (503)")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("GET /tun returned %d: %s", resp.StatusCode, string(body))
			continue
		}

		var cfg proxy.TunConfig
		decodeErr := json.NewDecoder(resp.Body).Decode(&cfg)
		_ = resp.Body.Close()
		if decodeErr != nil {
			lastErr = fmt.Errorf("decode tun config: %w", decodeErr)
			continue
		}

		return &cfg, nil
	}

	// 错误只说明重试本身，失败步骤由调用方命名。
	return nil, fmt.Errorf("after retries: %w", lastErr)
}

// 它会出现在桌面通知里，而平台脚本失败时可能产生大段引用的命令输出。
const maxHelperFailureReason = 512

// 连接套接字本身就是信号（父进程接受后发现没有 fd），原因作为这条连接的载荷传递，托盘因此
// 能直接说出失败的步骤。尽力而为：父进程已不在就无人可告知。
func notifyStartFailure(socketPath string, reason error) {
	if socketPath == "" {
		return
	}
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck

	if payload := failurePayload(reason); len(payload) > 0 {
		_, _ = conn.Write(payload)
	}
}

// 桌面通知渲染不了换行，而这个套接字只承载一条消息。超限文本保留两端：开头是失败的步骤，
// 结尾是脚本的 "failed near:" 摘要。
func failurePayload(reason error) []byte {
	if reason == nil {
		return nil
	}
	msg := strings.Join(strings.Fields(reason.Error()), " ")
	if len(msg) > maxHelperFailureReason {
		const ellipsis = " ... "
		keep := maxHelperFailureReason - len(ellipsis)
		msg = msg[:keep/2] + ellipsis + msg[len(msg)-(keep-keep/2):]
	}
	return []byte(msg)
}

// util.Command 把整条命令行和该输出的转义副本打包进错误，不适合展示给用户；unix create 脚本
// 会在输出里指明失败的步骤，这段文本必须保留（见 failurePayload）。
func execScriptWithOutput(shell, scriptPath string, args ...string) error {
	out, err := exec.Command(shell, append([]string{scriptPath}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sendFdToParent(socketPath string, tunFd int) error {
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial socket %s: %w", socketPath, err)
	}
	defer conn.Close() //nolint:errcheck

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var sendErr error
	err = rawConn.Write(func(fd uintptr) bool {
		rights := unix.UnixRights(tunFd)
		err := unix.Sendmsg(int(fd), []byte{1}, rights, nil, 0)
		if err != nil {
			sendErr = fmt.Errorf("sendmsg: %w", err)
		}
		return err == nil
	})
	if err != nil {
		return fmt.Errorf("write control: %w", err)
	}
	if sendErr != nil {
		return sendErr
	}

	log.Info("[TUN-HELPER] fd sent via unix socket", "socket", socketPath)
	return nil
}

// 关闭写端（EOF）即通知 helper 退出；关闭时删掉文件，重试或关闭 TUN 时才不留残骸。
type fifoWriter struct {
	*os.File
	path string
}

func (w *fifoWriter) Close() error {
	err := w.File.Close()
	os.Remove(w.path) //nolint:errcheck
	return err
}

// fd 作为辅助数据传递；套接字唯一承载的载荷，是在能发送 fd 之前放弃的 helper 的失败原因。
func ReceiveFd(listener net.Listener) (int, error) {
	if err := setAcceptDeadline(listener, 30*time.Second); err != nil {
		return -1, fmt.Errorf("set accept deadline: %w", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		return -1, fmt.Errorf("accept: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("get syscall conn: %w", err)
	}

	var (
		result  int
		recvErr error
	)
	ctrlErr := rawConn.Control(func(fd uintptr) {
		if err := unix.SetNonblock(int(fd), false); err != nil {
			recvErr = fmt.Errorf("set blocking: %w", err)
			return
		}
		defer unix.SetNonblock(int(fd), true) //nolint:errcheck

		// 缓冲区要容纳 notifyStartFailure 可能发来的失败原因（见 maxHelperFailureReason）。
		buf := make([]byte, maxHelperFailureReason)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, err := unix.Recvmsg(int(fd), buf, oob, 0)
		if err != nil {
			recvErr = fmt.Errorf("recvmsg: %w", err)
			return
		}

		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			recvErr = fmt.Errorf("parse control message: %w", err)
			return
		}
		if len(scms) == 0 {
			// 不带 fd 的连接正是放弃的 helper 在报告原因。
			if reason := strings.TrimSpace(string(buf[:n])); reason != "" {
				recvErr = fmt.Errorf("the tun helper exited: %s", reason)
				return
			}
			recvErr = fmt.Errorf("no control message received")
			return
		}

		fds, err := unix.ParseUnixRights(&scms[0])
		if err != nil {
			recvErr = fmt.Errorf("parse unix rights: %w", err)
			return
		}
		if len(fds) == 0 {
			recvErr = fmt.Errorf("no fd received")
			return
		}

		// 让 TUN fd 不进入子进程：客户端可能仍持有它时 exec pkexec，继承的副本会让接口保持
		// 挂接，使清理与下一次启动都以 "device or resource busy" 失败。
		unix.CloseOnExec(fds[0])

		result = fds[0]
	})
	if ctrlErr != nil {
		return -1, fmt.Errorf("control: %w", ctrlErr)
	}
	if recvErr != nil {
		return -1, recvErr
	}

	return result, nil
}

func setAcceptDeadline(listener net.Listener, d time.Duration) error {
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("not a unix listener")
	}
	return unixListener.SetDeadline(time.Now().Add(d))
}
