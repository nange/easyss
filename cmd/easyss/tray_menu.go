//go:build !headless

package main

import (
	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
)

// radioOption 是一组互斥勾选项中的一项。
type radioOption struct {
	key     string
	label   string
	checked bool
}

// radioMenu 是一组互斥勾选项：点击已选中项保持原状，选中新项后取消其他项。
type radioMenu struct {
	items map[string]*systray.MenuItem
	apply func(key string)
}

func newRadioMenu(m *systray.Menu, options []radioOption, apply func(string)) *radioMenu {
	r := &radioMenu{items: make(map[string]*systray.MenuItem, len(options)), apply: apply}
	for _, opt := range options {
		key := opt.key
		r.items[key] = m.AddCheckbox(opt.label, opt.checked, func() { go r.selectKey(key) })
	}
	return r
}

// 平台不会自动翻转勾选，因此这里读到的仍是点击前的状态。
func (r *radioMenu) selectKey(key string) {
	if r.items[key].IsChecked() {
		return
	}
	r.apply(key)
	for k, item := range r.items {
		item.SetChecked(k == key)
	}
}

// proxyObjectMenu 是"代理对象"的两个开关。
type proxyObjectMenu struct {
	browser *systray.MenuItem
	tun     *systray.MenuItem
}

func newProxyObjectMenu(m *systray.Menu, cfg *config.ClientConfig, onBrowser, onTun func()) *proxyObjectMenu {
	return &proxyObjectMenu{
		browser: m.AddCheckbox("浏览器(设置系统代理)", !cfg.Local.DisableSysProxy, onBrowser),
		tun:     m.AddCheckbox("系统全局流量(Tun2socks)", cfg.Local.EnableTun2socks, onTun),
	}
}

func (p *proxyObjectMenu) browserChecked() bool { return p.browser.IsChecked() }

func (p *proxyObjectMenu) tunChecked() bool { return p.tun.IsChecked() }

func (p *proxyObjectMenu) setTunChecked(checked bool) { p.tun.SetChecked(checked) }

// toggleCheck 把一次点击解释为切换：平台不会翻转勾选，因此先乐观更新，失败再回滚。
func toggleCheck(item *systray.MenuItem, apply func(on bool) error, onError func(on bool, err error)) {
	on := !item.IsChecked()
	item.SetChecked(on)
	if err := apply(on); err != nil {
		item.SetChecked(!on)
		onError(on, err)
	}
}
