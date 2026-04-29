//go:build unit

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/client/web"
)

func TestServeStaticFilesSetsSecurityHeadersForRootIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	serveStaticFiles(c, "/", web.StaticFS)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	ct := w.Header().Get("Content-Type")
	require.Contains(t, ct, "text/html")
}

func TestSafeRedirectLocation_DropsQueryString(t *testing.T) {
	// Forwarding RawQuery verbatim into the Location header would let a `next=http://evil.example` parameter ride along on the redirect; the redirect itself stays same-origin, but downstream JS that consumes `next` could be tricked into navigating off-origin
	// safeRedirectLocation must therefore drop the query entirely
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/foo?next=http://evil.example&x=1", nil)

	safeRedirectLocation(c, "foo")
	// Gin buffers the status until something is written; flush so the recorder reports the real code
	c.Writer.WriteHeaderNow()

	require.Equal(t, http.StatusMovedPermanently, w.Code)
	require.Equal(t, "/foo/", w.Header().Get("Location"))
}

func TestSafeRedirectLocation_NoQueryStringStillSlashSuffix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/bar", nil)

	safeRedirectLocation(c, "bar")
	c.Writer.WriteHeaderNow()

	require.Equal(t, http.StatusMovedPermanently, w.Code)
	require.Equal(t, "/bar/", w.Header().Get("Location"))
}
