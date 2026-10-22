//go:build !headless

package tray

import (
	"runtime"
	"sync"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/cmd/easyss/icon"
	"github.com/nange/easyss/v3/log"
)

// 通知标题，也是托盘 tooltip 的默认文本。
const AppName = "Easyss"

// Shell 是托盘外壳：句柄、菜单树、通知与退出信号。菜单部件、更新状态与平台
// 状态各自持有，它只负责“显示”本身。
type Shell struct {
	// 菜单填好之前为 nil：darwin 的 systray.New 会立刻创建 NSStatusItem，
	// 提前创建会让用户看到一个空菜单的图标。Show 之后只读，并发读者必须在
	// Show 返回之后启动。
	tray *systray.SystemTray

	root      *systray.Menu
	built     chan struct{}
	closing   chan struct{}
	closeOnce sync.Once

	// systray 保护菜单项，但不保护图标/tooltip 字段，二者必须成对串行写。
	uiMu sync.Mutex
}

func NewShell() *Shell {
	return &Shell{
		root:    systray.NewMenu(),
		built:   make(chan struct{}),
		closing: make(chan struct{}),
	}
}

// Root 返回菜单树；构建阶段可写，Show 之后只读。
func (s *Shell) Root() *systray.Menu { return s.root }

// Closing 在托盘退出时关闭，供统计与更新循环感知。
func (s *Shell) Closing() <-chan struct{} { return s.closing }

// Show 创建句柄并显示；必须等菜单组装完成后调用。
func (s *Shell) Show() {
	s.tray = systray.New()
	if runtime.GOOS == "darwin" {
		// 模板图标只在 macOS 生效（单色，随菜单栏主题自适应）；Windows/Linux 用 SetIcon。
		s.tray.SetTemplateIcon(icon.TrayData)
	} else {
		s.tray.SetIcon(icon.TrayData)
	}
	s.tray.SetTooltip(AppName)
	s.tray.SetMenu(s.root)
	s.tray.Show()
}

func (s *Shell) Run() error { return s.tray.Run() }

func (s *Shell) Remove() {
	if s.tray == nil {
		return
	}
	s.tray.Remove()
}

func (s *Shell) MarkBuilt() { close(s.built) }

// WaitBuilt 等 buildTray 完成，之后 Remove 才有可终止的消息循环。
func (s *Shell) WaitBuilt() { <-s.built }

// ready 只决定可选通知是否发送，不参与任何流程控制。
func (s *Shell) ready() bool {
	select {
	case <-s.built:
		return true
	default:
		return false
	}
}

// RequestExit 广播退出信号：所有等待 closing 的循环都会醒来，重复调用无副作用。
func (s *Shell) RequestExit() {
	s.closeOnce.Do(func() { close(s.closing) })
}

// gogpu/systray 会丢弃平台错误，日志是“通知是否交给操作系统”的唯一痕迹。
func (s *Shell) Notify(msg string) {
	if msg == "" {
		return
	}
	log.Info("[SYSTRAY] notify", "msg", msg)
	if s.tray == nil {
		return
	}
	s.tray.ShowNotification(AppName, msg)
}

// notifyIfReady 跳过托盘未就绪时的通知，避免结果在无人可见时被吞掉。
func (s *Shell) NotifyIfReady(msg string) {
	if !s.ready() {
		log.Warn("[SYSTRAY] notify skipped: tray not ready", "msg", msg)
		return
	}
	s.Notify(msg)
}

// RebuildMenu 重新挂上整棵菜单树；systray 会把菜单打开期间的重建排队到关闭后应用。
func (s *Shell) RebuildMenu() {
	if s.tray == nil {
		return
	}
	s.tray.SetMenu(s.root)
}

// setIconAndTooltip 在同一把锁内成对写，避免主题切换读到半更新的组合。
func (s *Shell) SetIconAndTooltip(png []byte, tooltip string) {
	s.uiMu.Lock()
	defer s.uiMu.Unlock()
	s.setIconLocked(png)
	s.tray.SetTooltip(tooltip)
}

// 缺图标渲染支持时降级为仅刷新 tooltip。
func (s *Shell) SetTooltip(text string) {
	s.uiMu.Lock()
	defer s.uiMu.Unlock()
	s.tray.SetTooltip(text)
}

// 必须同时设置暗色模式图标槽位，否则 Windows 主题切换会用无徽标的图标覆盖徽标
// （其他平台上空操作）。
func (s *Shell) setIconLocked(png []byte) {
	if runtime.GOOS == "darwin" {
		s.tray.SetTemplateIcon(png)
	} else {
		s.tray.SetIcon(png)
	}
	s.tray.SetDarkModeIcon(png)
}
