package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/actors"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
)

func TestMiddlewareRateLimit_AllowsRequestsUpToConfiguredLimit(t *testing.T) {
	router, handlerCalls := newRateLimitTestRouter(t, 2, nil)

	first := performRateLimitRequest(t, router, "198.51.100.10:1001", "")
	second := performRateLimitRequest(t, router, "198.51.100.10:1001", "")

	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, http.StatusOK, second.Code)
	require.Equal(t, int32(2), handlerCalls.Load())
}

func TestMiddlewareRateLimit_BlocksRequestsAboveConfiguredLimitForSameIP(t *testing.T) {
	router, handlerCalls := newRateLimitTestRouter(t, 1, nil)

	first := performRateLimitRequest(t, router, "198.51.100.20:1001", "")
	second := performRateLimitRequest(t, router, "198.51.100.20:2002", "")

	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, http.StatusTooManyRequests, second.Code)
	require.Equal(t, int32(1), handlerCalls.Load())
}

func TestMiddlewareRateLimit_TracksLimitsPerClientIP(t *testing.T) {
	router, handlerCalls := newRateLimitTestRouter(t, 1, nil)

	clientAFirst := performRateLimitRequest(t, router, "198.51.100.30:1001", "")
	clientBFirst := performRateLimitRequest(t, router, "198.51.100.31:1001", "")
	clientASecond := performRateLimitRequest(t, router, "198.51.100.30:2002", "")

	require.Equal(t, http.StatusOK, clientAFirst.Code)
	require.Equal(t, http.StatusOK, clientBFirst.Code)
	require.Equal(t, http.StatusTooManyRequests, clientASecond.Code)
	require.Equal(t, int32(2), handlerCalls.Load())
}

func TestMiddlewareRateLimit_UsesForwardedClientIPFromTrustedProxy(t *testing.T) {
	router, handlerCalls := newRateLimitTestRouter(t, 1, []string{"10.0.0.0/8"})

	first := performRateLimitRequest(t, router, "10.1.2.3:1001", "203.0.113.9")
	second := performRateLimitRequest(t, router, "10.1.2.3:2002", "203.0.113.9")
	third := performRateLimitRequest(t, router, "10.1.2.3:3003", "203.0.113.10")

	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, http.StatusTooManyRequests, second.Code)
	require.Equal(t, http.StatusOK, third.Code)
	require.Equal(t, int32(2), handlerCalls.Load())
}

func TestMiddlewareRateLimit_SetsRetryAfter(t *testing.T) {
	router, _ := newRateLimitTestRouter(t, 1, nil)

	first := performRateLimitRequest(t, router, "198.51.100.40:1001", "")
	second := performRateLimitRequest(t, router, "198.51.100.40:1001", "")

	require.Equal(t, http.StatusOK, first.Code)
	require.Empty(t, first.Header().Get("Retry-After"))

	require.Equal(t, http.StatusTooManyRequests, second.Code)
	retryAfter, err := strconv.Atoi(second.Header().Get("Retry-After"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, retryAfter, 1)
	require.LessOrEqual(t, retryAfter, 60)
	require.Contains(t, second.Header().Get("Content-Type"), "application/json")
	require.Contains(t, second.Body.String(), "Too many requests")
}

func TestMiddlewareRateLimit_FailsOpen(t *testing.T) {
	// The Francis host is never started, so the limit can't be checked
	host := newRateLimitTestHost(t)
	rl, err := host.NewRateLimiter("test-limiter", 1, time.Minute)
	require.NoError(t, err)

	handlerCalls := &atomic.Int32{}
	router := gin.New()
	router.Use(MiddlewareRateLimit(rl))
	router.GET("/limited", func(c *gin.Context) {
		handlerCalls.Add(1)
		c.String(http.StatusOK, "ok")
	})

	for range 3 {
		res := performRateLimitRequest(t, router, "198.51.100.50:1001", "")
		require.Equal(t, http.StatusOK, res.Code)
	}
	require.Equal(t, int32(3), handlerCalls.Load())
}

// newRateLimitTestHost returns a Francis host for the rate limit tests, which is not started yet
func newRateLimitTestHost(t *testing.T) *actors.Host {
	t.Helper()

	t.Cleanup(config.SetTestConfig(map[string]any{
		"francisPeerAddress": actors.TestPeerAddress(t),
		"francisDatabaseDSN": ":memory:",
	}))

	host, err := actors.NewHost(actors.NewHostOptions{
		Log: slog.New(slog.DiscardHandler),
		DB:  db.NewTestDatabaseForServerTests(t),
	})
	require.NoError(t, err)

	return host
}

func newRateLimitTestRouter(t *testing.T, rpm int, trustedProxies []string) (*gin.Engine, *atomic.Int32) {
	t.Helper()

	// Rate limiters run on a Francis host, which must be started after they're registered
	host := newRateLimitTestHost(t)
	rl, err := host.NewRateLimiter("test-limiter", rpm, time.Minute)
	require.NoError(t, err)
	actors.RunTestHost(t, host)

	handlerCalls := &atomic.Int32{}
	router := gin.New()

	err = router.SetTrustedProxies(trustedProxies)
	require.NoError(t, err)

	router.Use(MiddlewareRateLimit(rl))
	router.GET("/limited", func(c *gin.Context) {
		handlerCalls.Add(1)
		c.String(http.StatusOK, "ok")
	})

	return router, handlerCalls
}

func performRateLimitRequest(t *testing.T, router http.Handler, remoteAddr string, forwardedFor string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	req.RemoteAddr = remoteAddr

	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	return recorder
}
