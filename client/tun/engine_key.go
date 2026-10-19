package tun

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// ErrNotFDPath 表示当前会话不是 fd 路径（没有提权 helper 传来的设备描述符）。
var ErrNotFDPath = errors.New("tun: not an fd-based session")

// validateEngineKey 在把 TUN fd 交给 tun2socks 之前，把引擎**必然**会拒绝的
// 配置先拒掉。
//
// 为什么需要它：`engine.Start` 的步骤是 general → restAPI → netstack，而
// netstack 内部才做 parseProxy → parseDevice → core.CreateStack。也就是说
// 失败可能发生在 fd 被接管之前。此时 fd 仍是本进程的裸 fd（Linux 上
// fdbased.New 失败不关 fd，darwin 上是否关取决于 iobased 内部），而引擎也
// 不会把它记进 _defaultDevice，`engine.Stop` 因此是空操作——fd 就泄漏了，
// 在 darwin/linux 的提权 helper 路径上表现为设备随 fd 存活到进程退出，helper
// 的关闭脚本还会因 "device or resource busy" 删不掉它。
//
// 可靠的做法不是事后猜 "引擎接管了吗"（fd 号会被复用；socket 与字符设备的
// dev/ino/rdev/mode 本身不足以区分两个不同的打开实例），而是让这类失败
// **不可能发生在交出 fd 之后**：下面三项是 parseDevice 之前仅有的失败源
// （Key.Interface 与 Key.RestAPI 在本项目里恒为空），它们在 Start 里都是
// 可以廉价、无副作用地判定的事实。
//
// 校验只读入参，不触碰引擎状态：log.ParseLevel 与 proxy.Parse 都是纯函数，
// url.Parse 也不会做网络 IO。
func validateEngineKey(key *engine.Key) error {
	if _, err := log.ParseLevel(key.LogLevel); err != nil {
		return fmt.Errorf("tun: invalid log level %q: %w", key.LogLevel, err)
	}

	// general 把小于 1s 的 UDPTimeout 判为非法（见 tun2socks 的 general 步骤）。
	// 本项目不会把它设成这种值，但 Start 是导出入口，仍按引擎的规则拦住。
	if d := key.UDPTimeout; d > 0 && d < time.Second {
		return fmt.Errorf("tun: invalid udp timeout %v: below one second", d)
	}

	if err := validateProxyURL(key.Proxy); err != nil {
		return err
	}
	return nil
}

// validateProxyURL 复刻 tun2socks 的 parseProxy：缺 scheme 时补 socks5://，
// 然后要求 url.Parse 与 proxy.Parse 都能接受。两者的失败都会发生在
// parseDevice 之前，因此必须在这里拦下。
func validateProxyURL(addr string) error {
	if addr == "" {
		return fmt.Errorf("tun: empty socks5 address")
	}

	raw := addr
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("tun: invalid socks5 address %q: %w", addr, err)
	}
	if _, err := proxy.Parse(u); err != nil {
		return fmt.Errorf("tun: unsupported socks5 address %q: %w", addr, err)
	}
	return nil
}
