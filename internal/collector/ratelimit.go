package collector

import (
	"sync"
	"time"
)

// rateLimiter enforces a per-source-IP packets-per-second limit.
// A zero or negative limit disables rate limiting.
type rateLimiter struct {
	limit   int
	mu      sync.Mutex
	sources map[string]*sourceCounter
}

type sourceCounter struct {
	count  int
	window time.Time
}

func newRateLimiter(pps int) *rateLimiter {
	return &rateLimiter{
		limit:   pps,
		sources: make(map[string]*sourceCounter),
	}
}

// allow returns true if the packet from srcIP should be processed.
// It uses a simple per-second sliding window.
func (rl *rateLimiter) allow(srcIP string) bool {
	if rl.limit <= 0 {
		return true
	}
	now := time.Now().Truncate(time.Second)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	sc, ok := rl.sources[srcIP]
	if !ok || sc.window != now {
		rl.sources[srcIP] = &sourceCounter{count: 1, window: now}
		return true
	}
	sc.count++
	return sc.count <= rl.limit
}

// cleanup removes stale entries older than 10 seconds to prevent unbounded growth.
// It should be called periodically.
func (rl *rateLimiter) cleanup() {
	if rl.limit <= 0 {
		return
	}
	cutoff := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, sc := range rl.sources {
		if sc.window.Before(cutoff) {
			delete(rl.sources, k)
		}
	}
}
