package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
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

func newRateLimitTestRouter(t *testing.T, rpm int, trustedProxies []string) (*gin.Engine, *atomic.Int32) {
	t.Helper()

	handlerCalls := &atomic.Int32{}
	router := gin.New()

	err := router.SetTrustedProxies(trustedProxies)
	require.NoError(t, err)

	router.Use(MiddlewareRateLimit(rpm))
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
