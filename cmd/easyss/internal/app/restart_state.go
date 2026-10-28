package app

import (
	"strconv"
	"strings"

	clientconfig "github.com/nange/easyss/v3/client/config"
)

// RestartState 是"以管理员权限重启"这个动作及其载荷。出现在命令行即表示要接管正在运行的
// 实例，因此空载荷也有效：若把它做成 bool，`-elevated-restart=` 会和"没传这个 flag"混为
// 一谈，新实例会按普通启动去抢锁、失败后静默退出。
type RestartState struct {
	enabled     bool
	serverIndex int    // -1：沿用配置文件
	sysProxy    string // ""：沿用配置；on/off：托盘上的浏览器代理开关
	proxyRule   string // ""：沿用配置
	logLevel    string // ""：沿用配置
}

// Enabled 报告本次启动是否要接管正在运行的实例。
func (s *RestartState) Enabled() bool { return s.enabled }

// Apply 把交接过来的运行期选择写回配置快照。未启用时是空操作；服务器下标越界（UAC 期间
// 用户改了配置文件）时保留文件里的默认服务器。只改内存快照，不回写配置文件。
func (s *RestartState) Apply(cfg *clientconfig.ClientConfig) {
	if !s.enabled {
		return
	}
	if s.serverIndex >= 0 && s.serverIndex < len(cfg.Servers) {
		cfg.SetDefaultServerIndex(s.serverIndex)
	}
	switch s.sysProxy {
	case "on":
		cfg.Local.DisableSysProxy = false
	case "off":
		cfg.Local.DisableSysProxy = true
	}
	if s.proxyRule != "" {
		cfg.Routing.ProxyRule = s.proxyRule
	}
	if s.logLevel != "" {
		cfg.Log.Level = s.logLevel
	}
}

// String 供 flag 打印默认值。
func (s *RestartState) String() string { return s.encode() }

// IsBoolFlag 让 -elevated-restart 保持裸写可用（等价于"重启、不带载荷"）。带载荷时必须用
// 等号形式：flag 遇到第一个非 flag 参数就停止解析，空格形式会把载荷当位置参数丢掉。
func (s *RestartState) IsBoolFlag() bool { return true }

// Set 永不返回错误：它跑在 flag.Parse 里、也就是 UAC 授权之后，返回错误会让进程直接打印
// 用法并退出。载荷由本进程拼装，坏 key/坏值退化成"该项不覆盖"，格式 bug 由 round-trip
// 测试兜住。
func (s *RestartState) Set(v string) error {
	*s = RestartState{enabled: true, serverIndex: -1}
	switch v {
	case "", "true":
		return nil
	case "false":
		*s = RestartState{serverIndex: -1}
		return nil
	}
	for kv := range strings.SplitSeq(v, ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch key {
		case "server":
			if n, err := strconv.Atoi(val); err == nil {
				s.serverIndex = n
			}
		case "sysproxy":
			if val == "on" || val == "off" {
				s.sysProxy = val
			}
		case "rule":
			s.proxyRule = val
		case "log":
			s.logLevel = val
		}
	}
	return nil
}

// encode 是这条命令行的线格式。只放枚举与整数：格式没有转义规则，含逗号或空格的值
// （比如配置路径）必须继续走独立 flag。
func (s *RestartState) encode() string {
	if !s.enabled {
		return "false"
	}
	parts := make([]string, 0, 4)
	if s.serverIndex >= 0 {
		parts = append(parts, "server="+strconv.Itoa(s.serverIndex))
	}
	if s.sysProxy != "" {
		parts = append(parts, "sysproxy="+s.sysProxy)
	}
	if s.proxyRule != "" {
		parts = append(parts, "rule="+s.proxyRule)
	}
	if s.logLevel != "" {
		parts = append(parts, "log="+s.logLevel)
	}
	return strings.Join(parts, ",")
}
