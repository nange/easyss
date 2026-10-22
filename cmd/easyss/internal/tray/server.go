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

// ServerMenu 是"选择服务器"子菜单：菜单项与地址一一对应。
type ServerMenu struct {
	items []*systray.MenuItem
	addrs []string
}

func NewServerMenu(m *systray.Menu, cfg *clientconfig.ClientConfig, onSelect func(int)) *ServerMenu {
	addrs := cfg.ServerListAddrs()
	if len(addrs) == 0 {
		addrs = []string{cfg.DefaultServerAddr()}
	}
	def := cfg.DefaultServerAddr()
	s := &ServerMenu{addrs: addrs, items: make([]*systray.MenuItem, 0, len(addrs))}
	for idx, addr := range addrs {
		s.items = append(s.items, m.AddCheckbox(addr, addr == def, func() { onSelect(idx) }))
	}
	return s
}

func (s *ServerMenu) Checked(idx int) bool { return s.items[idx].IsChecked() }

func (s *ServerMenu) Addr(idx int) string { return s.addrs[idx] }

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
			item.SetLabel(formatTitle(s.addrs[i], rttMs, downSpeed))
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
