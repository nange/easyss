//go:build !headless

package tray

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/util"
)

// ServerMenu 是"选择服务器"子菜单。items/addrs/labels 按下标对齐：addrs 是服务器身份，
// 切换与匹配默认服务器都用它；labels 只用于菜单展示（配置了 name 时即 name）。
type ServerMenu struct {
	items  []*systray.MenuItem
	addrs  []string
	labels []string
}

func NewServerMenu(m *systray.Menu, cfg *clientconfig.ClientConfig, onSelect func(int)) *ServerMenu {
	addrs := cfg.ServerListAddrs()
	labels := cfg.ServerListNames()
	if len(addrs) == 0 {
		addrs = []string{cfg.DefaultServerAddr()}
		labels = addrs
	}
	def := cfg.DefaultServerAddr()
	s := &ServerMenu{addrs: addrs, labels: labels, items: make([]*systray.MenuItem, 0, len(addrs))}
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
	for i, item := range s.items {
		item.SetChecked(i == idx)
	}
}

// updateMetrics 只刷新当前选中的服务器项。
func (s *ServerMenu) updateMetrics(rttMs float64, downSpeed string) {
	for i, item := range s.items {
		if item.IsChecked() {
			item.SetLabel(formatTitle(s.labels[i], rttMs, downSpeed))
			return
		}
	}
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
