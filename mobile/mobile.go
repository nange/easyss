// Package mobile 是 EasySS 客户端核心的 gomobile 绑定。日志器由 Start 按 SimpleConfig
// 的 log_level/log_file_path 装配：路径为空只写 stdout（桥接到 logcat），否则额外落文件。
package mobile

import (
	"fmt"
	"sync"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/version"
)

var (
	mCore *runner.Core
	mMu   sync.Mutex
)

func Start(cfg *config.SimpleConfig) error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore != nil {
		return fmt.Errorf("already started, call Stop first")
	}

	clientCfg, err := clientconfig.BuildSimpleConfig(cfg)
	if err != nil {
		return err
	}

	// forward DNS 的闸门由桌面会话在 TUN 起来后发布（client.Client.TunForwardingEnabled），
	// mobile 直接调用 runner.Run、没有这一层：放行只会得到一个永远拒答的 :53。
	if clientCfg.Local.EnableForwardDNS {
		return fmt.Errorf("enable_forward_dns is not supported on mobile")
	}

	// 必须在 runner.Run 之前用 log.Init 装配：默认 logger 的处理器持有静态 LevelInfo，
	// 只调 log.SetLevel 改不动它；输出仍写 stdout，给了文件路径时额外落一份文件。
	log.Init(clientCfg.Log)

	core, err := runner.Run(clientCfg)
	if err != nil {
		// 失败路径必须自己收尾文件输出：核心未建立时 Stop 会因 mCore == nil 早退，
		// 写入器从包级 logger 可达，*os.File 的 finalizer 不兜底，句柄会留到进程退出。
		_ = log.CloseFileOutput()
		return err
	}
	mCore = core
	return nil
}

func Stop() {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore == nil {
		return
	}

	mCore.Stop()
	// 释放 Start 打开的文件输出，否则遗留句柄会挡住宿主在 Windows 上删除或轮转日志。
	_ = log.CloseFileOutput()
	mCore = nil
}
func Version() string {
	return version.Tag()
}
