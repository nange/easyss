package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

// builtinDNSCoolDown is how long the builtin dns servers are skipped after
// they all failed for a query, so that a persistently unreachable builtin
// dns (e.g. blocked by the network) does not slow down every query with its
// timeouts. Once the cool-down expires a single retry is allowed so that a
// recovered network is picked up again.
const builtinDNSCoolDown = 1 * time.Minute

var (
	builtinDNSMu     sync.Mutex
	builtinDNSDown   bool
	builtinDNSDownAt time.Time
)

// BuiltinDNSAvailable reports whether the builtin dns servers should be
// tried for a query. It returns false during the cool-down after
// MarkBuiltinDNSUnavailable, so queries go straight to the system dns
// servers; once the cool-down expires a retry is allowed.
func BuiltinDNSAvailable() bool {
	builtinDNSMu.Lock()
	defer builtinDNSMu.Unlock()
	if !builtinDNSDown {
		return true
	}
	return time.Since(builtinDNSDownAt) >= builtinDNSCoolDown
}

// MarkBuiltinDNSUnavailable marks the builtin dns servers as unavailable,
// skipping them for builtinDNSCoolDown. It is called when a query against
// all builtin dns servers failed.
func MarkBuiltinDNSUnavailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = true
	builtinDNSDownAt = time.Now()
	builtinDNSMu.Unlock()
}

// MarkBuiltinDNSAvailable clears the unavailable state, called when a query
// against a builtin dns server succeeds.
func MarkBuiltinDNSAvailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSMu.Unlock()
}

// QueryWithBuiltinFirst runs try against the builtin dns servers and falls
// back to the system dns servers when they are unavailable. The builtin
// servers are skipped entirely during the cool-down after a failure, so a
// persistently unreachable builtin dns does not slow down every query with
// its timeouts.
func QueryWithBuiltinFirst(builtin, system []string, try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if len(builtin) == 0 {
		return try(system)
	}
	if BuiltinDNSAvailable() {
		reply, err := try(builtin)
		if err == nil {
			MarkBuiltinDNSAvailable()
			return reply, nil
		}
		MarkBuiltinDNSUnavailable()
		log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "err", err)
	}
	return try(system)
}
