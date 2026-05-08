package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	rlCleanupInterval = 5 * time.Minute
	rlBucketTTL       = 2 * time.Minute
)

// bucket is a per-IP token-bucket state.
type bucket struct {
	mu       sync.Mutex
	tokens   float64
	lastSeen time.Time
}

// allow refills tokens based on elapsed time and returns whether the request
// should be permitted. Token count is capped at burst.
func (b *bucket) allow(rps, burst float64) bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rps
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastSeen = now
	if b.tokens >= 1.0 {
		b.tokens--
		return true
	}
	return false
}

// rateLimiter is a per-IP token-bucket rate limiter using only stdlib.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64
	burst   float64
	stop    chan struct{}
}

// newRateLimiter constructs a rate limiter. rps is the sustained rate; burst
// is the maximum burst size (defaults to 2×rps when <= 0). A background
// goroutine prunes stale buckets every 5 minutes.
func newRateLimiter(rps, burst int) *rateLimiter {
	r := float64(rps)
	b := float64(burst)
	if b <= 0 {
		b = r * 2
	}
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		rps:     r,
		burst:   b,
		stop:    make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) cleanup() {
	t := time.NewTicker(rlCleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cutoff := time.Now().Add(-rlBucketTTL)
			rl.mu.Lock()
			for ip, bkt := range rl.buckets {
				bkt.mu.Lock()
				seen := bkt.lastSeen
				bkt.mu.Unlock()
				if seen.Before(cutoff) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stop:
			return
		}
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	bkt, ok := rl.buckets[ip]
	if !ok {
		bkt = &bucket{tokens: rl.burst, lastSeen: time.Now()}
		rl.buckets[ip] = bkt
	}
	rl.mu.Unlock()
	return bkt.allow(rl.rps, rl.burst)
}

// RateLimit returns an http.Handler middleware that enforces per-IP token-bucket
// rate limits. When rps <= 0 the middleware is a no-op (rate limiting disabled).
// RealIP middleware must run before this middleware so that r.RemoteAddr reflects
// the client IP rather than a proxy address.
func RateLimit(rps, burst int) func(http.Handler) http.Handler {
	if rps <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	rl := newRateLimiter(rps, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !rl.allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
