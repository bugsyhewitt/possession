package replay

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// hostLimiter is a per-host token-bucket rate limiter (D15). One bucket per
// host, sharing the same configured rate. Limiters are created lazily on
// first use to avoid pre-allocating for hosts we never hit.
type hostLimiter struct {
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
	buckets map[string]*rate.Limiter
	disabled bool
}

func newHostLimiter(perSecond float64, disabled bool) *hostLimiter {
	r := rate.Limit(perSecond)
	burst := 1
	if perSecond >= 1 {
		burst = int(perSecond)
	}
	return &hostLimiter{
		rate:     r,
		burst:    burst,
		buckets:  make(map[string]*rate.Limiter),
		disabled: disabled,
	}
}

// wait blocks until the limiter for host permits a request, or ctx is done.
// When disabled, wait returns nil immediately.
func (h *hostLimiter) wait(ctx context.Context, host string) error {
	if h == nil || h.disabled {
		return nil
	}
	h.mu.Lock()
	l, ok := h.buckets[host]
	if !ok {
		l = rate.NewLimiter(h.rate, h.burst)
		h.buckets[host] = l
	}
	h.mu.Unlock()
	return l.Wait(ctx)
}
