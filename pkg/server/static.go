package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/client"
	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
)

//go:generate ../../client/build.sh

const staticBaseDir = "dist"

func (s *Server) serveClient() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		// Add cache-control header for static assets to cache for 30 days
		addClientCacheHeaders(30 * 86400),
		func(c *gin.Context) {
			if !prepareStaticResponse(c) {
				return
			}

			// Serve the request from the embedded FS
			serveStaticFiles(c, c.Request.URL.Path, client.StaticFS)
		},
	}
}

// Invoked before serving static files from embedded FS or proxy
func prepareStaticResponse(c *gin.Context) (ok bool) {
	// Only respond to GET requests
	if c.Request.Method != "GET" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Not found"))
		return false
	}

	return true
}

// Serve static files from an embedded FS
func serveStaticFiles(c *gin.Context, reqPath string, filesystem fs.FS) {
	reqPath = strings.TrimLeft(reqPath, "/")

	// Check if the static file exists
	f, err := filesystem.Open(staticBaseDir + "/" + reqPath)
	if err != nil {
		// If there's no "index.html" at the end, try appending that
		if reqPath != "index.html" && !strings.HasSuffix(reqPath, "/index.html") {
			// ...but first make sure there's a trailing slash
			if reqPath != "" && !strings.HasSuffix(reqPath, "/") {
				redirect := reqPath + "/"
				if c.Request.URL.RawQuery != "" {
					redirect += "?" + c.Request.URL.RawQuery
				}
				c.Header("Location", redirect)
				c.Status(http.StatusMovedPermanently)
				return
			}
			serveStaticFiles(c, path.Join(reqPath, "index.html"), filesystem)
			return
		}
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Page not found"))
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Page not found"))
			return
		case errors.Is(err, fs.ErrPermission):
			AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Forbidden"))
			return
		default:
			AbortWithErrorJSON(c, err)
			return
		}
	}

	// If it's a directory, load the index.html file
	if stat.IsDir() {
		// Redirect if the directory name doesn't end in a slash
		if reqPath != "" && !strings.HasSuffix(reqPath, "/") {
			redirect := reqPath + "/"
			if c.Request.URL.RawQuery != "" {
				redirect += "?" + c.Request.URL.RawQuery
			}
			c.Header("Location", redirect)
			c.Status(http.StatusMovedPermanently)
			return
		}

		// Load the index.html file in the directory instead
		serveStaticFiles(c, path.Join(reqPath, "index.html"), filesystem)
		return
	}

	// Apply page security headers to the actual file being served, including SPA index fallbacks
	ext := strings.ToLower(path.Ext(reqPath))
	if ext == ".html" || ext == ".htm" {
		setPageSecurityHeaders(c.Writer)
	}

	// File should implement io.Seeker when it's not a directory
	fseek, ok := f.(io.ReadSeekCloser)
	if !ok {
		AbortWithErrorJSON(c, fmt.Errorf("file %s does not implement io.ReadSeekCloser", stat.Name()))
		return
	}

	http.ServeContent(c.Writer, c.Request, stat.Name(), stat.ModTime(), fseek)
}

func addClientCacheHeaders(cacheMaxAge int64) func(c *gin.Context) {
	cfg := config.Get()

	cacheControlHeader := fmt.Sprintf("public, max-age=%d", cacheMaxAge)

	// Go does not save the last modification time for embedded files
	// As a workaround, we use the time the app build time
	buildTime := buildinfo.GetBuildDate()
	lastModifiedHeader := buildTime.Format(time.RFC1123)

	if cfg.Dev.DisableClientCache {
		return func(c *gin.Context) {
			c.Header("Cache-Control", "no-cache")
		}
	}

	return func(c *gin.Context) {
		if isNotModified(c) {
			// Request has already been aborted
			return
		}

		// Add cache-control and last-modified header
		c.Header("Cache-Control", cacheControlHeader)
		if lastModifiedHeader != "" {
			c.Header("Last-Modified", lastModifiedHeader)
		}
	}
}

func isNotModified(c *gin.Context) bool {
	// Check if there's an If-Modified-Since header
	ims := c.Request.Header.Get("If-Modified-Since")
	if ims == "" {
		return false
	}

	// If there's no build time, it's always modified
	buildTime := buildinfo.GetBuildDate()
	imsDate, err := time.Parse(time.RFC1123, ims)
	// Ignore headers with invalid dates
	if err != nil || !imsDate.After(buildTime) {
		return false
	}

	c.AbortWithStatus(http.StatusNotModified)
	return true
}

func setPageSecurityHeaders(w http.ResponseWriter) {
	// Content-Security-Policy:
	//   default-src 'none'  — deny everything not explicitly allowed
	//   script-src 'self' 'wasm-unsafe-eval'
	//                       — JS only from same origin (Vite/SRI bundles); 'wasm-unsafe-eval' is required for mlkem-wasm
	//   style-src 'self'    — CSS only from same origin (Tailwind bundle)
	//   img-src 'self'      — images from same origin
	//   font-src 'self'     — fonts from same origin
	//   connect-src 'self'  — fetch/XHR/WebSocket to same origin only
	//   manifest-src 'self' — PWA manifest from same origin
	//   worker-src 'self'   — service worker (VitePWA sw.js) from same origin
	//   frame-ancestors 'none' — equivalent to X-Frame-Options: DENY but CSP level 2+
	//   base-uri 'none'     — prevent <base> tag injection that would reroute relative URLs
	//   form-action 'none'  — no HTML form submissions (SPA, all interaction is via fetch)
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'self' 'wasm-unsafe-eval'; "+
			"style-src 'self'; "+
			"img-src 'self'; "+
			"font-src 'self'; "+
			"connect-src 'self'; "+
			"manifest-src 'self'; "+
			"worker-src 'self'; "+
			"frame-ancestors 'none'; "+
			"base-uri 'none'; "+
			"form-action 'none'",
	)

	// Legacy clickjacking protection for browsers that don't support CSP frame-ancestors
	w.Header().Set("X-Frame-Options", "DENY")

	// Disable FLOC
	w.Header().Set("Permissions-Policy", "interest-cohort=()")

	// Disable indexing by search engines
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
}
