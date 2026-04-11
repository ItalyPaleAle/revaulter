package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIPRateLimiterPerKey(t *testing.T) {
	l := newIPRateLimiter(5, 5)
	now := time.Unix(1_700_000_000, 0)

	// First 5 requests from ip1 succeed, then it is blocked
	for range 5 {
		require.True(t, l.allow("ip1", now), "ip1 should have tokens remaining")
	}
	require.False(t, l.allow("ip1", now), "ip1 should be throttled")

	// ip2 is independent and still has its full burst
	for range 5 {
		require.True(t, l.allow("ip2", now), "ip2 should have its own bucket")
	}
	require.False(t, l.allow("ip2", now), "ip2 should be throttled")
}

func TestIPRateLimiterRefill(t *testing.T) {
	l := newIPRateLimiter(10, 10)
	now := time.Unix(1_700_000_000, 0)

	// Drain the bucket
	for range 10 {
		require.True(t, l.allow("ip", now))
	}
	require.False(t, l.allow("ip", now))

	// Half a second at 10 rps => 5 tokens regenerated
	now = now.Add(500 * time.Millisecond)
	for range 5 {
		require.True(t, l.allow("ip", now))
	}
	require.False(t, l.allow("ip", now))
}

func TestIPRateLimiterEvictionCap(t *testing.T) {
	l := newIPRateLimiter(1, 1)
	l.maxSize = 3
	now := time.Unix(1_700_000_000, 0)

	require.True(t, l.allow("a", now))
	require.True(t, l.allow("b", now.Add(time.Second)))
	require.True(t, l.allow("c", now.Add(2*time.Second)))
	require.Len(t, l.buckets, 3)

	// Adding a 4th key should evict the oldest ("a")
	require.True(t, l.allow("d", now.Add(3*time.Second)))
	require.Len(t, l.buckets, 3)
	_, aStillThere := l.buckets["a"]
	require.False(t, aStillThere, "oldest key should have been evicted")
}
