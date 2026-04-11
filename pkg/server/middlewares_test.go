//go:build unit

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
)

func TestGetRequestIDUsesTrustedHeaderWhenValid(t *testing.T) {
	t.Cleanup(config.SetTestConfig(map[string]any{
		"trustedRequestIdHeader": "X-Request-ID",
	}))

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-Request-ID", "trace-123:edge_1")

	id, err := (&Server{}).getRequestID(c)
	require.NoError(t, err)
	require.Equal(t, "trace-123:edge_1", id)
}

func TestGetRequestIDRejectsInvalidTrustedHeader(t *testing.T) {
	t.Cleanup(config.SetTestConfig(map[string]any{
		"trustedRequestIdHeader": "X-Request-ID",
	}))

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-Request-ID", "trace bad")

	id, err := (&Server{}).getRequestID(c)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.NotEqual(t, "trace bad", id)
}

func TestValidTrustedRequestID(t *testing.T) {
	require.True(t, validTrustedRequestID("abc-DEF_123.trace:edge"))
	require.False(t, validTrustedRequestID(""))
	require.False(t, validTrustedRequestID("bad value"))
	require.False(t, validTrustedRequestID("bad/value"))
	require.False(t, validTrustedRequestID("bad\nvalue"))
}
