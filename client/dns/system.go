package dns

import (
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// sysDNSFunc 负责发现系统 DNS 服务器，可在测试中覆盖。
var sysDNSFunc = util.SysDNS

// systemDNSServersFunc 返回格式化后的系统 DNS 服务器列表，供回退路径使用，
// 可在测试中覆盖。
var systemDNSServersFunc = SystemDNSServers

const systemDNSCacheTTL = 5 * time.Minute

var (
	systemDNSMu     sync.Mutex
	systemDNSCached []string
	systemDNSTime   time.Time
)

// SystemDNSServers 以 host:port 地址的形式返回系统 DNS 服务器，从操作系统
// 惰性发现并短暂缓存。当所有内置直连 DNS 服务器都不可用时作为回退使用。
// 空结果也会被缓存，这样失败的发现（例如缓慢的 ipconfig 调用）不会在每次
// DNS 查询时重复执行。
func SystemDNSServers() []string {
	systemDNSMu.Lock()
	defer systemDNSMu.Unlock()

	if time.Since(systemDNSTime) < systemDNSCacheTTL {
		return systemDNSCached
	}

	servers, err := sysDNSFunc()
	if err != nil {
		log.Warn("[DNS] get system dns servers", "err", err)
	}
	var addrs []string
	for _, s := range servers {
		if s == "" {
			continue
		}
		addrs = append(addrs, net.JoinHostPort(s, "53"))
	}
	systemDNSCached = addrs
	systemDNSTime = time.Now()
	return addrs
}
