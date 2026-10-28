//go:build !headless

package tray

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/util"
)

// ServerMenu 是"选择服务器"子菜单。items/addrs/labels/shown/rendered 按下标对齐：addrs 是
// 服务器身份，切换与匹配默认服务器都用它；labels 是配置里的名字（通知文案要用），shown 是它
// 截断到显示上限后的菜单标签。
type ServerMenu struct {
	// mu 保护 metrics 与标题写入，持有期间会做平台的同步写入（darwin 是主线程 waitUntilDone
	// 往返），因此调用方不得是托盘回调/UI 线程。
	mu sync.Mutex
	// setLabel 是条目标题的下发路径，单独成字段便于测试统计重写次数。
	setLabel func(*systray.MenuItem, string)
	items    []*systray.MenuItem
	addrs    []string
	labels   []string
	shown    []string
	// rendered 是上一轮下发的标题：没变化的条目不再重写，每轮只推真正变化的行。
	rendered []string
	column   float64
	metrics  string
}

func NewServerMenu(m *systray.Menu, cfg *clientconfig.ClientConfig, onSelect func(int)) *ServerMenu {
	addrs := cfg.ServerListAddrs()
	labels := cfg.ServerListNames()
	if len(addrs) == 0 {
		addrs = []string{cfg.DefaultServerAddr()}
		labels = addrs
	}
	def := cfg.DefaultServerAddr()
	// 每一行都要截断：菜单宽度由最宽的行决定，Windows 的加速键列（指标）跟着菜单右边缘走，
	// 只要有一行超长，选中行的指标就会被它推到很右边。
	shown := make([]string, len(labels))
	for i, label := range labels {
		shown[i] = truncateLabel(label)
	}
	s := &ServerMenu{
		addrs:    addrs,
		labels:   labels,
		shown:    shown,
		rendered: slices.Clone(shown),
		column:   metricsColumn(labels),
		setLabel: (*systray.MenuItem).SetLabel,
		items:    make([]*systray.MenuItem, 0, len(addrs)),
	}
	for idx, addr := range addrs {
		s.items = append(s.items, m.AddCheckbox(shown[idx], addr == def, func() { onSelect(idx) }))
	}
	return s
}

func (s *ServerMenu) Checked(idx int) bool { return s.items[idx].IsChecked() }

func (s *ServerMenu) Addr(idx int) string { return s.addrs[idx] }

// DisplayName 返回通知与错误文案里的服务器标识：配置了 name 时为 "name (host:port)"，
// 否则就是地址；两者相同时只显示一次。
func (s *ServerMenu) DisplayName(idx int) string {
	if label := s.labels[idx]; label != s.addrs[idx] {
		return label + " (" + s.addrs[idx] + ")"
	}
	return s.addrs[idx]
}

func (s *ServerMenu) IndexOf(addr string) int {
	for i, candidate := range s.addrs {
		if candidate == addr {
			return i
		}
	}
	return -1
}

func (s *ServerMenu) SetChecked(idx int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.checkedLocked()
	for i, item := range s.items {
		// 一次切换会两次进入这里，逐项同步写是每项一次主线程往返，没变的就别写。
		if want := i == idx; item.IsChecked() != want {
			item.SetChecked(want)
		}
	}
	if prev != idx {
		// 指标属于当前连接：换服务器后旧数据已经失效，等下一轮统计再填。
		s.metrics = ""
	}
	s.refreshLocked()
}

// updateMetrics 用最近一次统计刷新标题：只有勾选中的服务器带指标。
func (s *ServerMenu) updateMetrics(rttMs float64, downSpeed string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics = metricsText(rttMs, downSpeed)
	s.refreshLocked()
}

// refreshLocked 只把标题变了的条目下发到原生菜单：统计循环每 2s 跑一轮，全量重写会让
// darwin 每轮做 N 次主线程同步往返（setTitle: 的 waitUntilDone:YES）。
func (s *ServerMenu) refreshLocked() {
	for i, item := range s.items {
		title := s.titleLocked(i)
		if s.rendered[i] == title {
			continue
		}
		s.setLabel(item, title)
		s.rendered[i] = title
	}
}

// titleLocked 返回条目应显示的标题：只有勾选中的条目带指标。
func (s *ServerMenu) titleLocked(idx int) string {
	if s.metrics == "" || !s.items[idx].IsChecked() {
		return s.shown[idx]
	}
	return formatTitle(s.shown[idx], s.metrics, s.column)
}

func (s *ServerMenu) checkedLocked() int {
	for i, item := range s.items {
		if item.IsChecked() {
			return i
		}
	}
	return -1
}

// startStatsLoop 轮询本地 /stats 并刷新选中项；closing 关闭后返回。
func (s *ServerMenu) StartStatsLoop(cfg *clientconfig.ClientConfig, closing <-chan struct{}) {
	url := fmt.Sprintf("http://%s/stats", util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	httpClient := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-ticker.C:
			rttMs, downSpeed := fetchStats(httpClient, url)
			s.updateMetrics(rttMs, downSpeed)
		case <-closing:
			return
		}
	}
}

func fetchStats(client *http.Client, url string) (rttMs float64, downSpeed string) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()

	var snap struct {
		AvgRTTMs           float64 `json:"avg_rtt_ms"`
		DownloadSpeedHuman string  `json:"download_speed_human"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return 0, ""
	}
	return snap.AvgRTTMs, snap.DownloadSpeedHuman
}
