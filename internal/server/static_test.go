package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/client/web"
	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/config"
)

func TestServeStaticFilesCachePolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	files := fstest.MapFS{
		"dist/index.html":               {Data: []byte("index")},
		"dist/sw.js":                    {Data: []byte("service worker")},
		"dist/registerSW.js":            {Data: []byte("register")},
		"dist/manifest.webmanifest":     {Data: []byte("manifest")},
		"dist/index.LcWOOJ-q.js":        {Data: []byte("fingerprinted")},
		"dist/assets/icon.abcdefgh.svg": {Data: []byte("fingerprinted icon")},
		"dist/app.js":                   {Data: []byte("mutable")},
		"dist/app.development.js":       {Data: []byte("mutable named asset")},
		"dist/app.abcdefg.js":           {Data: []byte("short hash")},
		"dist/app.abcdefghi.js":         {Data: []byte("long hash")},
		"dist/index.abcdefgh.html":      {Data: []byte("mutable page")},
		"dist/config.abcdefgh.json":     {Data: []byte("mutable config")},
	}

	tests := []struct {
		name         string
		requestPath  string
		cacheControl string
	}{
		{name: "root index", requestPath: "/", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "index alias", requestPath: "/index.html", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "service worker", requestPath: "/sw.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "service worker registration", requestPath: "/registerSW.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "web manifest", requestPath: "/manifest.webmanifest", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "unhashed asset", requestPath: "/app.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "nonhash segment", requestPath: "/app.development.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "short hash", requestPath: "/app.abcdefg.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "long hash", requestPath: "/app.abcdefghi.js", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "hash-looking html", requestPath: "/index.abcdefgh.html", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "hash-looking config", requestPath: "/config.abcdefgh.json", cacheControl: "no-cache, max-age=0, must-revalidate"},
		{name: "fingerprinted script", requestPath: "/index.LcWOOJ-q.js?version=1", cacheControl: "public, max-age=2592000"},
		{name: "fingerprinted nested asset", requestPath: "/assets/icon.abcdefgh.svg", cacheControl: "public, max-age=2592000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tt.requestPath, nil)

			serveStaticFiles(c, c.Request.URL.Path, files)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, tt.cacheControl, w.Header().Get("Cache-Control"))
		})
	}
}

func TestServeStaticFilesPreservesDirectorySlashSemantics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	files := fstest.MapFS{
		"dist/index.html":      {Data: []byte("root")},
		"dist/docs/index.html": {Data: []byte("docs")},
	}
	tests := []struct {
		name         string
		requestPath  string
		wantStatus   int
		wantLocation string
	}{
		{name: "existing directory redirects", requestPath: "/docs", wantStatus: http.StatusMovedPermanently, wantLocation: "/docs/"},
		{name: "existing directory index", requestPath: "/docs/", wantStatus: http.StatusOK},
		{name: "missing path redirects once", requestPath: "/missing", wantStatus: http.StatusMovedPermanently, wantLocation: "/missing/"},
		{name: "missing path with slash is not found", requestPath: "/missing/", wantStatus: http.StatusNotFound},
		{name: "protocol-relative input stays local", requestPath: "//evil.example", wantStatus: http.StatusMovedPermanently, wantLocation: "/evil.example/"},
		{name: "backslash input stays local", requestPath: `\evil.example`, wantStatus: http.StatusMovedPermanently, wantLocation: "/evil.example/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.URL.Path = tt.requestPath

			serveStaticFiles(c, c.Request.URL.Path, files)
			c.Writer.WriteHeaderNow()

			require.Equal(t, tt.wantStatus, w.Code)
			require.Equal(t, tt.wantLocation, w.Header().Get("Location"))
		})
	}
}

func TestServeStaticFilesConditionalRequestsAfterResolution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousBuildDate := buildinfo.BuildDate
	buildinfo.BuildDate = "2026-09-22T12:00:00Z"
	t.Cleanup(func() {
		buildinfo.BuildDate = previousBuildDate
	})
	files := fstest.MapFS{
		"dist/index.html": {Data: []byte("index")},
	}

	tests := []struct {
		name                string
		requestPath         string
		ifModifiedSince     string
		wantStatus          int
		wantSecurityHeaders bool
	}{
		{name: "older", requestPath: "/", ifModifiedSince: "Mon, 21 Sep 2026 12:00:00 GMT", wantStatus: http.StatusOK, wantSecurityHeaders: true},
		{name: "equal", requestPath: "/", ifModifiedSince: "Tue, 22 Sep 2026 12:00:00 GMT", wantStatus: http.StatusNotModified, wantSecurityHeaders: true},
		{name: "newer", requestPath: "/", ifModifiedSince: "Wed, 23 Sep 2026 12:00:00 GMT", wantStatus: http.StatusNotModified, wantSecurityHeaders: true},
		{name: "malformed", requestPath: "/", ifModifiedSince: "not-a-date", wantStatus: http.StatusOK, wantSecurityHeaders: true},
		{name: "missing", requestPath: "/missing/", ifModifiedSince: "Wed, 23 Sep 2026 12:00:00 GMT", wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			c.Request.Header.Set("If-Modified-Since", tt.ifModifiedSince)

			serveStaticFiles(c, c.Request.URL.Path, files)
			c.Writer.WriteHeaderNow()

			require.Equal(t, tt.wantStatus, w.Code)
			require.NotEqual(t, "public, max-age=2592000", w.Header().Get("Cache-Control"))
			if tt.wantSecurityHeaders {
				require.Equal(t, "no-cache, max-age=0, must-revalidate", w.Header().Get("Cache-Control"))
				require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
				require.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
			}
		})
	}
}

func TestServeStaticFilesReusesAdvertisedValidator(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousBuildDate := buildinfo.BuildDate
	buildinfo.BuildDate = "2026-09-22T12:00:00Z"
	t.Cleanup(func() {
		buildinfo.BuildDate = previousBuildDate
	})
	files := fstest.MapFS{
		"dist/index.html":        {Data: []byte("index")},
		"dist/index.abcdefgh.js": {Data: []byte("fingerprinted")},
	}
	tests := []struct {
		name         string
		requestPath  string
		cacheControl string
		wantCSP      bool
	}{
		{name: "mutable page", requestPath: "/", cacheControl: "no-cache, max-age=0, must-revalidate", wantCSP: true},
		{name: "fingerprinted asset", requestPath: "/index.abcdefgh.js", cacheControl: "public, max-age=2592000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			firstRecorder := httptest.NewRecorder()
			firstContext, _ := gin.CreateTestContext(firstRecorder)
			firstContext.Request = httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			serveStaticFiles(firstContext, firstContext.Request.URL.Path, files)
			firstContext.Writer.WriteHeaderNow()

			lastModified := firstRecorder.Header().Get("Last-Modified")
			require.Equal(t, "Tue, 22 Sep 2026 12:00:00 GMT", lastModified)

			secondRecorder := httptest.NewRecorder()
			secondContext, _ := gin.CreateTestContext(secondRecorder)
			secondContext.Request = httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			secondContext.Request.Header.Set("If-Modified-Since", lastModified)
			serveStaticFiles(secondContext, secondContext.Request.URL.Path, files)
			secondContext.Writer.WriteHeaderNow()

			require.Equal(t, http.StatusNotModified, secondRecorder.Code)
			require.Equal(t, tt.cacheControl, secondRecorder.Header().Get("Cache-Control"))
			if tt.wantCSP {
				require.NotEmpty(t, secondRecorder.Header().Get("Content-Security-Policy"))
			}
		})
	}
}

func TestServeClientRejectsUnsupportedMethodsWithoutPublicCaching(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	server := &Server{}
	router.NoRoute(server.serveClient()...)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/index.html", nil)

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotEqual(t, "public, max-age=2592000", w.Header().Get("Cache-Control"))
}

func TestServeStaticFilesHonorsDisabledClientCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := config.Get().Dev.DisableClientCache
	config.Get().Dev.DisableClientCache = true
	t.Cleanup(func() {
		config.Get().Dev.DisableClientCache = previous
	})
	files := fstest.MapFS{
		"dist/index.abcdefgh.js": {Data: []byte("fingerprinted")},
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/index.abcdefgh.js", nil)

	serveStaticFiles(c, c.Request.URL.Path, files)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

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
	// Forwarding RawQuery verbatim into the Location header would let a `next=http://evil.example` parameter ride along on the redirect
	// The redirect itself stays same-origin, but downstream JS that consumes `next` could be tricked into navigating off-origin
	// safeRedirectLocation must therefore drop the query entirely
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/foo?next=http://evil.example&x=1", nil)

	safeRedirectLocation(c, "foo")
	// Gin buffers the status until something is written
	// Flush so the recorder reports the real code
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
