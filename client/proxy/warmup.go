package proxy

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/nange/easyss/v3/log"
)

// WarmUp primes the transport's connection pools right after startup, so the
// first real request of each traffic class does not pay the cold-start cost
// (dial + TLS + HTTP/2). It waits a random jitter first, so startup traffic is
// not a fixed, machine-timed event, then primes the pools with real probe
// requests to the server's /v3/probe endpoint — the same request the
// degradation detector issues, visible only to the user's own server.
//
// jitterMin..jitterMax randomize the warm-up moment; timeout bounds the whole
// warm-up (jitter + connection establishment). Best-effort by contract: the
// failure is logged here and returned so the caller can decide what to do with
// it, but startup must never depend on warm-up. A nil error can also mean the
// warm-up was skipped (server closing or quit during the jitter), and a
// non-nil error does not mean the warm-up was useless: the connection may be
// established while the probe that confirms it did not answer in time.
func (s *Socks5Server) WarmUp(jitterMin, jitterMax, timeout time.Duration) error {
	if s == nil || s.closing.Load() {
		return nil
	}
	if jitterMax > 0 {
		d := jitterMin
		if span := jitterMax - jitterMin; span > 0 {
			d += time.Duration(rand.Float64() * float64(span))
		}
		select {
		case <-time.After(d):
		case <-s.quit:
			// Shutting down during the jitter: the warm-up is skipped, not
			// failed.
			log.Debug("[WARMUP] skipped, server closing")
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := s.handler.Transport().WarmUp(ctx); err != nil {
		log.Warn("[WARMUP] failed", "err", err)
		return err
	}
	log.Info("[WARMUP] done")
	return nil
}
