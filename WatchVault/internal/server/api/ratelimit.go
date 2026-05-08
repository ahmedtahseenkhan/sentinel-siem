package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	vaultRLCleanupInterval = 5 * time.Minute
	vaultRLBucketTTL       = 2 * time.Minute
)

type rlBucket struct {
	mu       sync.Mutex
	tokens   float64
	lastSeen time.Time
}

func (b *rlBucket) allow(rps, burst float64) bool {
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

type vaultRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rlBucket
	rps     float64
	burst   float64
}

func newVaultRateLimiter(rps, burst int) *vaultRateLimiter {
	r := float64(rps)
	b := float64(burst)
	if b <= 0 {
		b = r * 2
	}
	rl := &vaultRateLimiter{
		buckets: make(map[string]*rlBucket),
		rps:     r,
		burst:   b,
	}
	go func() {
		t := time.NewTicker(vaultRLCleanupInterval)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-vaultRLBucketTTL)
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
		}
	}()
	return rl
}

func (rl *vaultRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	bkt, ok := rl.buckets[ip]
	if !ok {
		bkt = &rlBucket{tokens: rl.burst, lastSeen: time.Now()}
		rl.buckets[ip] = bkt
	}
	rl.mu.Unlock()
	return bkt.allow(rl.rps, rl.burst)
}

// rateLimitMiddleware returns an http.Handler middleware that enforces per-IP
// token-bucket rate limits. When rps <= 0 the middleware is a no-op.
func rateLimitMiddleware(rps, burst int) func(http.Handler) http.Handler {
	if rps <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	rl := newVaultRateLimiter(rps, burst)
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
