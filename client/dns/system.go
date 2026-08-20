package dns

import (
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// sysDNSFunc discovers the system dns servers, overridable in tests.
var sysDNSFunc = util.SysDNS

// systemDNSServersFunc returns the formatted system dns server list consumed
// by the fallback paths, overridable in tests.
var systemDNSServersFunc = SystemDNSServers

const systemDNSCacheTTL = 5 * time.Minute

var (
	systemDNSMu     sync.Mutex
	systemDNSCached []string
	systemDNSTime   time.Time
)

// SystemDNSServers returns the system dns servers as host:port addresses,
// discovered lazily from the os and cached briefly. It is used as a fallback
// when all builtin direct dns servers are unavailable. An empty result is
// cached as well so that a failing discovery (e.g. a slow `ipconfig` call)
// is not repeated on every dns query.
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
