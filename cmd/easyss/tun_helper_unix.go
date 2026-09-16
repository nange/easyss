//go:build darwin || linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// fifoOpenResult 保存阻塞式 FIFO 写打开的结果。
type fifoOpenResult struct {
	f   *os.File
	err error
}

// openFifoForWriteAsync 在后台以写模式打开 fifoPath：对 FIFO 的 open(2) 会阻塞
// 直到出现读取方，而这里的读取方是通过 stdin 重定向启动的特权辅助进程。
func openFifoForWriteAsync(fifoPath string) <-chan fifoOpenResult {
	ch := make(chan fifoOpenResult, 1)
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		ch <- fifoOpenResult{f: f, err: err}
	}()
	return ch
}

// releaseFifoOpen 解除 openFifoForWriteAsync 发起的写打开阻塞，并关闭它产生的
// 文件。放弃等待的调用方必须使用它：删除 FIFO 并不能解除一个已在等待读取方的
// open(2)，否则该 goroutine（连同它的文件描述符）会在进程的整个生命周期内泄漏。
// 此处打开读端可以让挂起的 open 完成；它是非阻塞的，不需要写入方。
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

// runTunHelper 是长期运行的特权 TUN 辅助进程的入口。它通过 GET /tun 从主进程
// 获取配置，打开 TUN 设备，设置路由和 DNS，通过 Unix 域套接字把文件描述符传回，
// 然后阻塞读取 stdin。当 stdin 返回 EOF（主进程关闭了 FIFO 或已崩溃）时，
// 它执行清理并退出。
func runTunHelper(httpAddr, fdSocketPath, logFilePath, logLevel string) int {
	if httpAddr == "" || fdSocketPath == "" {
		fmt.Fprintf(os.Stderr, "[TUN-HELPER] missing required flags\n")
		return 1
	}

	// 父进程阻塞在 ReceiveFd 中等待辅助进程连接 fd 套接字，因此一个在能发送 fd
	// 之前就放弃的辅助进程必须自己去敲这个套接字：放任不管的话，父进程会一直等到
	// 整个 accept 超时，30 秒后才报告超时，而不是刚刚发生的失败。失败原因随同这条
	// 连接一并传递，托盘可以直接展示它，而不必把用户引向日志文件。使用 defer 保证
	// 下面的每个提前返回都被覆盖，包括以后新增的返回路径；已发送 fd 的辅助进程
	// 则保持沉默。
	var (
		fdSent  bool
		failure error
	)
	defer func() {
		if !fdSent {
			notifyStartFailure(fdSocketPath, failure)
		}
	}()

	// giveUp 记录辅助进程退出的原因，写入日志并返回退出码。记录的失败原因正是
	// notifyStartFailure 交给父进程的内容。
	giveUp := func(step string, err error) int {
		failure = fmt.Errorf("%s: %w", step, err)
		log.Error("[TUN-HELPER] "+step, "err", err)
		return 1
	}

	// 1. 尽早初始化日志器，使所有错误都出现在日志文件中（不会经由 stderr 丢失到
	//    /dev/null）。
	log.Init(logFilePath, logLevel)

	// 2. 通过 HTTP 从主进程获取 TUN 配置。
	cfg, err := fetchTunConfig(httpAddr)
	if err != nil {
		return giveUp("fetch tun config", err)
	}
	log.Info("[TUN-HELPER] config received", "device", cfg.Device)

	// 3. 获取独占文件锁，确保同一时刻只有一个辅助进程在运行。如果前一个辅助进程
	//    仍在清理中，我们会阻塞等待它退出、内核释放锁（即使 kill -9 也有效）。
	lockFile, err := os.OpenFile("/tmp/easyss-tun.lock", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return giveUp("open lock file", err)
	}
	if err := util.FlockWait(lockFile, 30*time.Second); err != nil {
		lockFile.Close() //nolint:errcheck
		return giveUp("acquire lock", err)
	}
	log.Info("[TUN-HELPER] lock acquired")
	defer lockFile.Close() //nolint:errcheck

	// 4. 在修改系统 DNS 之前保存原始配置。
	originDNS, err := util.SysDNS()
	if err != nil {
		log.Warn("[TUN-HELPER] read original dns", "err", err)
	}
	log.Info("[TUN-HELPER] original dns saved", "dns", originDNS)

	// 5. 打开 TUN 设备。
	tunFd, actualDevice, err := openTunDevice(cfg.Device)
	if err != nil {
		return giveUp("open tun device", err)
	}
	log.Info("[TUN-HELPER] device created", "requested", cfg.Device, "actual", actualDevice)

	// 延迟清理：退出时移除路由并恢复 DNS。
	defer func() {
		log.Info("[TUN-HELPER] cleaning up routes and DNS")
		_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
			cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)
		removeLeftoverDevice(actualDevice)
		_ = util.RestoreSysDNSForTun(actualDevice, originDNS)
		log.Info("[TUN-HELPER] cleanup done")
	}()

	// 给内核一点时间初始化接口。
	log.Info("[TUN-HELPER] waiting for kernel interface init")
	time.Sleep(200 * time.Millisecond)

	// 6. 清理上次 TUN 会话遗留的过期路由。
	log.Info("[TUN-HELPER] cleaning stale routes")
	_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
		cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)

	// 7. 运行 create 脚本（ifconfig/ip + route add）。
	log.Info("[TUN-HELPER] creating routes and configuring interface")
	if err := runCreateScript(actualDevice, cfg.TunIP, cfg.TunGW, cfg.LocalGateway,
		cfg.TunIPV6Sub, cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6); err != nil {
		_ = unix.Close(tunFd)
		return giveUp("run create script", err)
	}
	log.Info("[TUN-HELPER] routes and interface configured")

	// 8. 设置系统 DNS。
	if cfg.DNSAddr != "" {
		log.Info("[TUN-HELPER] setting system dns", "dns", cfg.DNSAddr)
		if err := util.SetSysDNSForTun(actualDevice, []string{cfg.DNSAddr}); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}

	// 9. 通过 Unix 域套接字把 TUN fd 发送给主进程。
	log.Info("[TUN-HELPER] sending tun fd to parent", "socket", fdSocketPath)
	if err := sendFdToParent(fdSocketPath, tunFd); err != nil {
		_ = unix.Close(tunFd)
		return giveUp("send fd to parent", err)
	}
	fdSent = true

	// 10. 关闭 fd（它已经发送给父进程）。
	_ = unix.Close(tunFd)
	log.Info("[TUN-HELPER] fd sent and closed")

	log.Info("[TUN-HELPER] ready, waiting for shutdown signal on stdin")

	// 11. 阻塞读取 stdin 直到 EOF。主进程关闭 FIFO 写端来发出关闭信号；若主进程
	//     崩溃（即使是被 kill -9），内核也会关闭它。
	//
	//     等待期间定期校验 TUN 路由是否仍然存在：macOS 在睡眠/唤醒或网络变更后
	//     可能清除非持久路由，从而静默禁用 TUN 模式（流量不再进入设备）。旧的
	//     纯 TUN 守护进程每 10 秒重新添加路由以应对睡眠/唤醒（ba6c894）；
	//     这个临时辅助进程对 TUN 路由本身保持了同样的行为。
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(os.Stdin)
		close(stdinDone)
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stdinDone:
			log.Info("[TUN-HELPER] received shutdown signal")
			return 0
		case <-ticker.C:
			if err := ensureTunRoutes(actualDevice, cfg); err != nil {
				log.Warn("[TUN-HELPER] route keep-alive check failed", "device", actualDevice, "err", err)
			}
			// NetworkManager 在连接变更时会重写链路 DNS 设置，可能把 DNS 默认路由
			// 交还给物理链路，使域名解析再次绕过隧道。
			if cfg.DNSAddr != "" {
				if err := util.EnsureSysDNSForTun(actualDevice, []string{cfg.DNSAddr}); err != nil {
					log.Warn("[TUN-HELPER] dns keep-alive check failed", "device", actualDevice, "err", err)
				}
			}
		}
	}
}

// tunRouteProbes 是必须被 TUN 路由覆盖的目标，用于校验睡眠/唤醒或网络变更后
// 路由是否仍然存在。darwin/linux/Windows 的 create 脚本把 1.0.0.0/8（以及直到
// 128.0.0.0/1 的全部网段）路由进 TUN 设备，因此 1.1.1.1——一个真实且广泛使用的
// DNS/HTTPS 目标——必须解析到它。如果这些探测地址与脚本发生漂移，keep-alive
// 会永远报告失败，因此 tun_helper_linux_test.go 断言每个探测地址都落在 create
// 脚本定义的路由块内。
var tunRouteProbes = []string{"1.1.1.1"}

// probeRoutedViaDevice 用 cmd 查询 probe 中的每个地址，并报告其中是否有任何一个
// 经由 TUN 设备解析：TUN 路由就位时，被覆盖的地址会解析到 TUN 设备而绝不会
// 走物理默认路由，因此查询输出必须包含 marker（设备名）。返回最后一次查询的
// 输出和错误，调用方可以据此记录检查失败的原因。
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

// fetchTunConfig 通过 GET /tun 从主进程获取 TUN 配置。它会带退避重试最长约
// 10 秒，以防 HTTP 服务器尚未就绪。
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
		// 每次迭代都关闭 body：重试循环最多运行十次，若用 defer 关闭，之前每次
		// 响应的 body 都会一直打开到函数返回。
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

	// 这个错误额外说明的是重试本身：调用方负责命名失败步骤。
	return nil, fmt.Errorf("after retries: %w", lastErr)
}

// maxHelperFailureReason 限制辅助进程交给父进程的失败文本长度：它会出现在桌面
// 通知中，而平台脚本失败时可能产生大段引用的命令输出。
const maxHelperFailureReason = 512

// notifyStartFailure 告诉正在 ReceiveFd 中等待的父进程：本辅助进程在能发送 fd
// 之前就放弃了，以及放弃的原因。连接套接字本身就是信号——父进程接受连接后发现
// 其中没有 fd——原因则作为这条连接的载荷一并传递，这样托盘可以直接说出失败的
// 步骤，而不必指向日志文件。这是尽力而为的操作：父进程已不存在时就无人可告知了。
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

// failurePayload 把 reason 渲染成父进程展示的单行文本：桌面通知无法渲染平台脚本
// 失败时产生的换行，而这个套接字只承载一条消息。超过上限的文本保留两端——开头是
// 失败的步骤，结尾是脚本的 "failed near:" 摘要——并丢弃中间重复的输出。
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

// execScriptWithOutput 运行平台脚本，并连同错误一起返回脚本自身的输出。
// util.Command 会把整条命令行和该输出的 Go 引号转义副本打包进错误里，这对日志行
// 没问题，但不适合父进程展示给用户的内容：unix create 脚本会在输出中指明失败的
// 步骤，这段文本必须保留下来（参见 failurePayload）。
//
// 错误本身不带动作名（例如 "run create script"）：其调用方已经通过 giveUp 命名了
// 正在运行的步骤，重复只会让通知更长。
func execScriptWithOutput(shell, scriptPath string, args ...string) error {
	out, err := exec.Command(shell, append([]string{scriptPath}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sendFdToParent 连接到 socketPath 处的 Unix 套接字，并通过 SCM_RIGHTS 发送
// TUN 文件描述符。
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

// fifoWriter 包装 FIFO 写端，并在关闭时删除 FIFO 文件，这样重试或关闭 TUN 时
// 不会积累残留文件。FIFO 用于生命周期信号：关闭写端（EOF）即通知辅助进程退出。
type fifoWriter struct {
	*os.File
	path string
}

func (w *fifoWriter) Close() error {
	err := w.File.Close()
	os.Remove(w.path) //nolint:errcheck
	return err
}

// ReceiveFd 在 Unix 域套接字监听器上接受单个连接，并通过 SCM_RIGHTS 接收文件
// 描述符。fd 纯粹作为辅助数据传递；这个套接字唯一承载的载荷，是一个在拥有可发送
// fd 之前就放弃的辅助进程的失败原因（参见 notifyStartFailure）。
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
		// 切换到阻塞模式，让 Recvmsg 等待数据。
		if err := unix.SetNonblock(int(fd), false); err != nil {
			recvErr = fmt.Errorf("set blocking: %w", err)
			return
		}
		defer unix.SetNonblock(int(fd), true) //nolint:errcheck

		// 缓冲区容纳 notifyStartFailure 可能发送的、替代 fd 的失败原因
		// （参见 maxHelperFailureReason）。
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
			// 放弃的辅助进程不带 fd 连接，正是为了报告这一点，并写入原因：
			// 这个原因就是托盘必须展示的内容。
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

		// 让 TUN fd 不进入任何子进程：客户端在可能仍持有该 fd 时会 exec pkexec
		// （它会再 exec 下一个辅助进程），继承的副本会让接口保持挂接状态，导致
		// 辅助进程的清理和下一次启动以 "device or resource busy" 失败。
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

// setAcceptDeadline 设置 Unix 监听器的 accept 截止时间。
func setAcceptDeadline(listener net.Listener, d time.Duration) error {
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("not a unix listener")
	}
	return unixListener.SetDeadline(time.Now().Add(d))
}
