package mobile

import (
	"fmt"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/version"
)

var (
	mCore *runner.Core
	mMu   sync.Mutex
)

// Warm-up tuning: the jitter randomizes the warm-up moment so startup traffic
// is not a fixed, machine-timed event; the timeout bounds the whole warm-up
// (jitter + connection establishment).
const (
	mobileWarmUpJitterMin = 300 * time.Millisecond
	mobileWarmUpJitterMax = 1000 * time.Millisecond
	mobileWarmUpTimeout   = 8 * time.Second
)

func Start(cfg *sharedconfig.SimpleConfig) error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore != nil {
		return fmt.Errorf("already started, call Stop first")
	}

	clientCfg, err := config.BuildSimpleConfig(cfg)
	if err != nil {
		return err
	}

	core, err := runner.Run(clientCfg)
	if err != nil {
		return err
	}
	mCore = core
	return nil
}

// WarmUp primes the first proxied connections so the first real requests do
// not pay the cold-start cost (dial + TLS + HTTP/2). Both scheduling pools are
// warmed with real probe requests to the server. It blocks (bounded by jitter
// + connection establishment) and should be called between the SOCKS5 server
// being ready and the VPN going live: the "connecting" state stays visible
// while it runs, and the VPN comes up with warm connections. Best-effort:
// failures are logged inside and never fail startup.
func WarmUp() error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore == nil {
		return fmt.Errorf("not started, call Start first")
	}
	if mCore.SocksServer == nil {
		return nil
	}
	mCore.SocksServer.WarmUp(mobileWarmUpJitterMin, mobileWarmUpJitterMax, mobileWarmUpTimeout)
	return nil
}

func Stop() {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore == nil {
		return
	}

	mCore.Stop()
	mCore = nil
}
func Version() string {
	return version.Tag()
}
