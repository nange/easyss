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

// 先拒掉 engine.Start 必然拒绝的配置（LogLevel、小于 1s 的 UDPTimeout、Socks5Addr）：这些
// 失败都在 parseDevice 之前，fd 还是裸 fd，engine.Stop 无从回收，设备会活到进程退出。
func validateEngineKey(key *engine.Key) error {
	if _, err := log.ParseLevel(key.LogLevel); err != nil {
		return fmt.Errorf("tun: invalid log level %q: %w", key.LogLevel, err)
	}

	// general 步骤把小于 1s 的 UDPTimeout 判为非法（见 tun2socks 的 general 步骤）。
	if d := key.UDPTimeout; d > 0 && d < time.Second {
		return fmt.Errorf("tun: invalid udp timeout %v: below one second", d)
	}

	if err := validateProxyURL(key.Proxy); err != nil {
		return err
	}
	return nil
}

// validateProxyURL 复刻 tun2socks 的 parseProxy：缺 scheme 时补 socks5://，
// 再要求 url.Parse 与 proxy.Parse 都接受——两者的失败都在 parseDevice 之前。
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
