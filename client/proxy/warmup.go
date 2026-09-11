package proxy

import (
	"context"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
)

// WarmUp primes the transport's connection pools right after the core
// started, so the first real request of each traffic class does not pay the
// cold-start cost (dial + TLS + HTTP/2). It primes the pools with real probe
// requests to the server's /v3/probe endpoint — the same request the
// degradation detector issues, visible only to the user's own server.
//
// The caller runs this in the background (runner.Core.StartWarmUp), so there
// is no jitter and no startup blocking here: timeout bounds the probe phase
// and callers pass config.WarmUpTimeout. Best-effort by contract: the failure
// is logged here and returned so the caller can decide what to do with it,
// but startup must never depend on warm-up. A nil error can equally mean the
// warm-up was skipped (no proxy server, or it is closing), and a non-nil
// error does not mean the warm-up was useless: the connection may be
// established while the probe that confirms it did not answer in time.
func (s *Socks5Server) WarmUp(timeout time.Duration) error {
	if s == nil || s.closing.Load() {
		return nil
	}
	if timeout <= 0 {
		timeout = config.WarmUpTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	if err := s.handler.Transport().WarmUp(ctx); err != nil {
		log.Warn("[WARMUP] failed",
			"err", err,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
		return err
	}
	log.Info("[WARMUP] done", "elapsed_ms", time.Since(start).Milliseconds())
	return nil
}
