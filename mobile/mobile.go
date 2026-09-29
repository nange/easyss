// Package mobile 是 EasySS 客户端核心的 gomobile 绑定。
//
// 日志器由 Start 按 SimpleConfig 的 log_level/log_file_path 装配，这两个字段
// 因此对 Android 主机应用生效：log_file_path 为空时只写进程 stdout——gomobile
// 已把它桥接到 logcat 的 GoLog 标签，app 的日志查看器正是这么收集的；传入应用
// 私有目录下的绝对路径（例如 filesDir/easyss.log）则额外落一份轮转文件，该文件
// 句柄由 Start 的失败路径与 Stop 释放（宿主删除/轮转日志文件不会被遗留句柄挡住）。
package mobile

import (
	"fmt"
	"sync"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
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

	// 日志器必须在 runner.Run 之前按配置装配：SimpleConfig 的
	// log_level/log_file_path 此前在这里被静默忽略，核心日志只能以包级默认
	// logger 的静态 info 级输出，配置里选的级别形同虚设。注意只调
	// log.SetLevel 同样无效——默认 logger 的处理器持有的是静态 LevelInfo，
	// atomicLevel 只被 log.Init 装配进处理器。输出目的地保持不变：仍然写
	// stdout（gomobile 把它桥接到 logcat 的 GoLog 标签），仅在给了文件路径时
	// 额外落一份文件。
	log.Init(clientCfg.Log.FilePath, clientCfg.Log.Level)

	core, err := runner.Run(clientCfg)
	if err != nil {
		// 失败路径必须自己收尾文件输出：核心没有建立（mCore 仍为 nil），Stop 会在
		// mCore == nil 时早退，CloseFileOutput 永远不会被调用；而写入器从包级
		// logger 可达，*os.File 的 finalizer 也不会兜底，句柄会一直留到进程退出。
		// 端口被占用、http_port 缺少 socks_port、forward DNS 绑定 53 失败等都是
		// 这条路径，且都发生在 "[EASYSS] client core ready" 之后——文件已经被打开。
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
	// 释放 Start 打开的文件输出（级别保持不变，日志仍会落到 stdout）：被打开的
	// 文件在 Windows 上无法删除或重命名，而 Start/Stop 是同一个进程里可以反复走
	// 的生命周期，宿主清理或轮转日志文件时不该被遗留句柄挡住。
	_ = log.CloseFileOutput()
	mCore = nil
}
func Version() string {
	return version.Tag()
}
