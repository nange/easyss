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
// while it runs, and the VPN comes up with warm connections.
//
// Best-effort by contract: a warm-up that could not be confirmed is returned
// (and logged by the proxy layer) so the caller can record it, but the caller
// must not fail startup because of it — a nil error can equally mean the
// warm-up was skipped (no SOCKS5 server, or shutting down). gomobile surfaces
// a non-nil error as a Java exception, so callers must handle it.
func WarmUp() error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore == nil {
		return fmt.Errorf("not started, call Start first")
	}
	if mCore.SocksServer == nil {
		// No local SOCKS5 proxy in this configuration: there is nothing to
		// warm, which is not a failure.
		return nil
	}
	return mCore.SocksServer.WarmUp(mobileWarmUpJitterMin, mobileWarmUpJitterMax, mobileWarmUpTimeout)
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
