//go:build unit

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/client"
)

func TestServeStaticFilesSetsSecurityHeadersForRootIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	serveStaticFiles(c, "/", client.StaticFS)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	ct := w.Header().Get("Content-Type")
	require.Contains(t, ct, "text/html")
}
