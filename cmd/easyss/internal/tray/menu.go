//go:build !headless

package tray

import (
	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
)

// RadioOption 是一组互斥勾选项中的一项。
type RadioOption struct {
	Key     string
	Label   string
	Checked bool
}

// RadioMenu 是一组互斥勾选项：点击已选中项保持原状，选中新项后取消其他项。
type RadioMenu struct {
	items map[string]*systray.MenuItem
	apply func(key string)
}

func NewRadioMenu(m *systray.Menu, options []RadioOption, apply func(string)) *RadioMenu {
	r := &RadioMenu{items: make(map[string]*systray.MenuItem, len(options)), apply: apply}
	for _, opt := range options {
		key := opt.Key
		r.items[key] = m.AddCheckbox(opt.Label, opt.Checked, func() { go r.selectKey(key) })
	}
	return r
}

// 平台不会自动翻转勾选，因此这里读到的仍是点击前的状态。
func (r *RadioMenu) selectKey(key string) {
	if r.items[key].IsChecked() {
		return
	}
	r.apply(key)
	for k, item := range r.items {
		item.SetChecked(k == key)
	}
}

// ObjectMenu 是"代理对象"的两个开关。
type ObjectMenu struct {
	browser *systray.MenuItem
	tun     *systray.MenuItem
}

func NewObjectMenu(m *systray.Menu, cfg *clientconfig.ClientConfig, onBrowser, onTun func()) *ObjectMenu {
	return &ObjectMenu{
		browser: m.AddCheckbox("浏览器(设置系统代理)", !cfg.Local.DisableSysProxy, onBrowser),
		tun:     m.AddCheckbox("系统全局流量(Tun2socks)", cfg.Local.EnableTun2socks, onTun),
	}
}

func (p *ObjectMenu) BrowserChecked() bool { return p.browser.IsChecked() }

// BrowserItem 返回"浏览器"开关，供通用 ToggleCheck 复用。
func (p *ObjectMenu) BrowserItem() *systray.MenuItem { return p.browser }

func (p *ObjectMenu) TunChecked() bool { return p.tun.IsChecked() }

func (p *ObjectMenu) SetTunChecked(checked bool) { p.tun.SetChecked(checked) }

// ToggleCheck 把一次点击解释为切换：平台不会翻转勾选，因此先乐观更新，失败再回滚。
func ToggleCheck(item *systray.MenuItem, apply func(on bool) error, onError func(on bool, err error)) {
	on := !item.IsChecked()
	item.SetChecked(on)
	if err := apply(on); err != nil {
		item.SetChecked(!on)
		onError(on, err)
	}
}
