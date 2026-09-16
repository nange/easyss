// Package mobile 是 EasySS 客户端核心的 gomobile 绑定。
//
// 传输预热不再从这里导出：runner.Run 会在核心启动后于后台调度预热
// （runner.Run），除非配置通过 transport.disable_warm_up 将其禁用。升级此
// AAR 的主机应用必须相应移除它们的 WarmUp() 调用——Start() 返回即表示
// 预热已被调度。此前用户在绑定阻塞于预热期间看到的"连接中"状态，
// 因此从这里不再可观察。
package mobile

import (
	"fmt"
	"sync"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/version"
)

var (
	mCore *runner.Core
	mMu   sync.Mutex
)

func Start(cfg *sharedconfig.SimpleConfig) error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore != nil {
		return fmt.Errorf("already started, call Stop first")
	}

	clientCfg, err := config.BuildSimpleConfig(cfg)
	if err != nil {
		return err
	}

	core, err := runner.Run(clientCfg)
	if err != nil {
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
	mCore = nil
}
func Version() string {
	return version.Tag()
}
