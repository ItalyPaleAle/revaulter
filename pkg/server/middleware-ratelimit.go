package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ipTokenBucket is a per-key token bucket: tokens refill continuously at `rate` tokens/second up to `burst`, consumed one per request
type ipTokenBucket struct {
	tokens float64
	last   time.Time
}

// ipRateLimiter is a per-IP token-bucket rate limiter
// It is non-blocking: if no token is available, the caller is expected to return HTTP 429.
type ipRateLimiter struct {
	rate    float64       // tokens per second
	burst   float64       // max tokens
	ttl     time.Duration // entries unused for longer than this are GC'd
	maxSize int           // hard cap on the number of tracked keys

	mu      sync.Mutex
	buckets map[string]*ipTokenBucket
	lastGC  time.Time
}

func newIPRateLimiter(rps int, burst int) *ipRateLimiter {
	if burst <= 0 {
		burst = rps
	}
	return &ipRateLimiter{
		rate:    float64(rps),
		burst:   float64(burst),
		ttl:     10 * time.Minute,
		maxSize: 10_000,
		buckets: make(map[string]*ipTokenBucket),
		lastGC:  time.Now(),
	}
}

// Consumes one token for key and reports whether the request may proceed.
func (l *ipRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		// Enforce a hard cap to prevent unbounded memory growth from a spoofed-IP flood
		// When full, evict the oldest entry
		if len(l.buckets) >= l.maxSize {
			l.evictOldestLocked()
		}
		b = &ipTokenBucket{
			tokens: l.burst,
			last:   now,
		}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *ipRateLimiter) gcLocked(now time.Time) {
	// Only sweep occasionally to keep per-request overhead low
	if now.Sub(l.lastGC) < time.Minute {
		return
	}

	l.lastGC = now
	cutoff := now.Add(-l.ttl)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

func (l *ipRateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	first := true
	for k, b := range l.buckets {
		if first || b.last.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.last
			first = false
		}
	}

	if !first {
		delete(l.buckets, oldestKey)
	}
}

// MiddlewareRateLimit returns a Gin middleware that enforces a per-client-IP request-per-second limit using a token bucket
// Requests that exceed the limit receive HTTP 429 Too Many Requests
func MiddlewareRateLimit(rps int) gin.HandlerFunc {
	limiter := newIPRateLimiter(rps, rps)
	return func(c *gin.Context) {
		key := c.ClientIP()
		if key == "" {
			key = c.Request.RemoteAddr
		}
		if !limiter.allow(key, time.Now()) {
			c.Header("Retry-After", "1")
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}
