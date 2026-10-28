//go:build !headless

package tray

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/util"
)

// ServerMenu 是"选择服务器"子菜单。items/addrs/labels 按下标对齐：addrs 是服务器身份，
// 切换与匹配默认服务器都用它；labels 只用于菜单展示（配置了 name 时即 name）。
type ServerMenu struct {
	// mu 保护 metrics 与标题写入：统计循环和切换流程会并发刷新同一批条目。
	mu      sync.Mutex
	items   []*systray.MenuItem
	addrs   []string
	labels  []string
	column  float64
	metrics string
}

func NewServerMenu(m *systray.Menu, cfg *clientconfig.ClientConfig, onSelect func(int)) *ServerMenu {
	addrs := cfg.ServerListAddrs()
	labels := cfg.ServerListNames()
	if len(addrs) == 0 {
		addrs = []string{cfg.DefaultServerAddr()}
		labels = addrs
	}
	def := cfg.DefaultServerAddr()
	s := &ServerMenu{addrs: addrs, labels: labels, column: metricsColumn(labels), items: make([]*systray.MenuItem, 0, len(addrs))}
	for idx, addr := range addrs {
		s.items = append(s.items, m.AddCheckbox(labels[idx], addr == def, func() { onSelect(idx) }))
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
		item.SetChecked(i == idx)
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

// refreshLocked 按当前选择重写所有条目标题。统计循环与切换流程会并发调到这里，
// 交错写会留下"两行都带指标"的中间态，所以锁要盖住整轮写入。
func (s *ServerMenu) refreshLocked() {
	for i, item := range s.items {
		item.SetLabel(s.titleLocked(i))
	}
}

// titleLocked 返回条目应显示的标题：只有勾选中的条目带指标。
func (s *ServerMenu) titleLocked(idx int) string {
	if s.metrics == "" || !s.items[idx].IsChecked() {
		return s.labels[idx]
	}
	return formatTitle(s.labels[idx], s.metrics, s.column)
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
