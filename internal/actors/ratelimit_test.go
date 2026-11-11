package actors

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter(t *testing.T) {
	h := newUnstartedTestHost(t, newTestDB(t), ":memory:")
	rl, err := h.NewRateLimiter("test-limiter", 2, time.Minute)
	require.NoError(t, err)
	RunTestHost(t, h)

	t.Run("admits the rate, then throttles", func(t *testing.T) {
		for range 2 {
			allowed, retryAfter := rl.Allow(t.Context(), "198.51.100.10")
			assert.True(t, allowed)
			assert.Zero(t, retryAfter)
		}

		allowed, retryAfter := rl.Allow(t.Context(), "198.51.100.10")
		assert.False(t, allowed)
		assert.Greater(t, retryAfter, time.Duration(0))
		assert.LessOrEqual(t, retryAfter, 30*time.Second, "one token refills every 30 seconds")
	})

	t.Run("keys are independent", func(t *testing.T) {
		allowed, _ := rl.Allow(t.Context(), "198.51.100.11")
		assert.True(t, allowed)

		allowed, _ = rl.Allow(t.Context(), "2001:db8::1")
		assert.True(t, allowed)
	})

	t.Run("fails open on an invalid key", func(t *testing.T) {
		// Keys can't contain slashes, so the check fails
		for range 3 {
			allowed, retryAfter := rl.Allow(t.Context(), "invalid/key")
			assert.True(t, allowed)
			assert.Zero(t, retryAfter)
		}
	})
}

func TestRateLimiterFailsOpen(t *testing.T) {
	requireAllowed := func(t *testing.T, rl *RateLimiter) {
		t.Helper()

		for range 3 {
			allowed, retryAfter := rl.Allow(t.Context(), "198.51.100.20")
			assert.True(t, allowed)
			assert.Zero(t, retryAfter)
		}
	}

	t.Run("before the host starts", func(t *testing.T) {
		h := newUnstartedTestHost(t, newTestDB(t), ":memory:")
		rl, err := h.NewRateLimiter("test-limiter", 1, time.Minute)
		require.NoError(t, err)

		requireAllowed(t, rl)
	})

	t.Run("after the host stops", func(t *testing.T) {
		h := newUnstartedTestHost(t, newTestDB(t), ":memory:")
		rl, err := h.NewRateLimiter("test-limiter", 1, time.Minute)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		errCh := make(chan error, 1)
		go func() {
			errCh <- h.Run(ctx, nil, nil)
		}()
		select {
		case <-h.Ready():
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the host to be ready")
		}
		cancel()
		err = <-errCh
		require.NoError(t, err)

		requireAllowed(t, rl)
	})
}

func TestHostRejectsCallsWhenNotRunning(t *testing.T) {
	h := newUnstartedTestHost(t, newTestDB(t), ":memory:")

	_, err := h.User("user-not-running").List(t.Context())
	require.ErrorIs(t, err, ErrHostNotRunning)

	_, err = h.User("user-not-running").Snapshot(t.Context())
	require.ErrorIs(t, err, ErrHostNotRunning)

	err = h.User("user-not-running").WaitForChange(t.Context(), "bell")
	require.ErrorIs(t, err, ErrHostNotRunning)
}

func TestNewRateLimiterValidates(t *testing.T) {
	h := newUnstartedTestHost(t, newTestDB(t), ":memory:")

	_, err := h.NewRateLimiter("", 1, time.Minute)
	require.Error(t, err)

	_, err = h.NewRateLimiter("zero-rate", 0, time.Minute)
	require.Error(t, err)

	_, err = h.NewRateLimiter("duplicate", 1, time.Minute)
	require.NoError(t, err)
	_, err = h.NewRateLimiter("duplicate", 1, time.Minute)
	require.Error(t, err, "names must be unique")
}

func TestRateLimiterAcrossReplicas(t *testing.T) {
	// Two replicas share the main database and a Francis SQLite file, and each registers the same limiter
	dbConn := newTestDB(t)
	francisDSN := filepath.Join(t.TempDir(), "francis.db")

	hostA := newUnstartedTestHost(t, dbConn, francisDSN)
	rlA, err := hostA.NewRateLimiter("test-limiter", 2, time.Minute)
	require.NoError(t, err)
	RunTestHost(t, hostA)

	hostB := newUnstartedTestHost(t, dbConn, francisDSN)
	rlB, err := hostB.NewRateLimiter("test-limiter", 2, time.Minute)
	require.NoError(t, err)
	RunTestHost(t, hostB)

	// The budget for a key is shared, whichever replica the calls arrive on
	allowed, _ := rlA.Allow(t.Context(), "198.51.100.60")
	assert.True(t, allowed)
	allowed, _ = rlB.Allow(t.Context(), "198.51.100.60")
	assert.True(t, allowed)

	allowed, retryAfter := rlA.Allow(t.Context(), "198.51.100.60")
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, time.Duration(0))
	allowed, _ = rlB.Allow(t.Context(), "198.51.100.60")
	assert.False(t, allowed)
}
