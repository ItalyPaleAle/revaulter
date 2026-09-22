package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/client/web"
	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/config"
)

//go:generate ../../client/web/build.sh

const staticBaseDir = "dist"

func (s *Server) serveClient() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		func(c *gin.Context) {
			if !prepareStaticResponse(c) {
				return
			}

			// Serve the request from the embedded FS
			serveStaticFiles(c, c.Request.URL.Path, web.StaticFS)
		},
	}
}

// Invoked before serving static files from embedded FS or proxy
func prepareStaticResponse(c *gin.Context) (ok bool) {
	// Only respond to GET requests
	if c.Request.Method != http.MethodGet {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Not found"))
		return false
	}

	return true
}

// Serve static files from an embedded FS
func serveStaticFiles(c *gin.Context, reqPath string, filesystem fs.FS) {
	// Normalize the request path before use
	// Backslashes are converted to forward slashes because some browsers parse "\" as "/" in Location headers, which would let "\evil.com" be interpreted as the protocol-relative URL "//evil.com"
	// path.Clean collapses "..", duplicate slashes, and trailing slashes, then prefixes with "/" and ensures the cleaned result is a host-relative absolute path
	normalizedPath := strings.ReplaceAll(reqPath, `\`, "/")
	hadTrailingSlash := strings.HasSuffix(normalizedPath, "/")
	reqPath = path.Clean("/" + normalizedPath)
	reqPath = strings.TrimPrefix(reqPath, "/")
	if hadTrailingSlash && reqPath != "" {
		reqPath += "/"
	}

	// Check if the static file exists
	f, err := filesystem.Open(staticBaseDir + "/" + reqPath)
	if err != nil {
		// If there's no "index.html" at the end, try appending that
		if reqPath != "index.html" && !strings.HasSuffix(reqPath, "/index.html") {
			// ...but first make sure there's a trailing slash
			if reqPath != "" && !strings.HasSuffix(reqPath, "/") {
				safeRedirectLocation(c, reqPath)
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
			safeRedirectLocation(c, reqPath)
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

	buildTime := buildinfo.GetBuildDate()
	setClientCacheHeaders(c, reqPath, 30*86400)
	http.ServeContent(c.Writer, c.Request, stat.Name(), buildTime, fseek)
}

// safeRedirectLocation emits a 301 redirect whose Location is guaranteed to be a host-relative URL starting with a single "/"
// This prevents user-controlled path segments from producing protocol-relative Locations such as "//evil.com" that would navigate the browser to a different origin
// The original request's query string is NOT forwarded to prevent certain attacks (static-file directory redirects don't need a query string anyways)
func safeRedirectLocation(c *gin.Context, reqPath string) {
	// reqPath has already been normalized by serveStaticFiles, so this just reattaches the leading slash and appends the trailing slash for the redirect
	redirect := "/" + reqPath + "/"
	c.Header("Location", redirect)
	c.Status(http.StatusMovedPermanently)
}

func setClientCacheHeaders(c *gin.Context, reqPath string, cacheMaxAge int64) {
	cfg := config.Get()

	if cfg.Dev.DisableClientCache {
		c.Header("Cache-Control", "no-cache")
		return
	}

	if isFingerprintAsset(reqPath) {
		c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheMaxAge))
		return
	}

	c.Header("Cache-Control", "no-cache, max-age=0, must-revalidate")
}

func isFingerprintAsset(reqPath string) bool {
	name := path.Base(reqPath)
	ext := strings.ToLower(path.Ext(name))
	if ext == "" {
		return false
	}
	switch ext {
	case ".avif", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".mjs", ".otf", ".png", ".svg", ".ttf", ".webp", ".woff", ".woff2":
	default:
		return false
	}

	stem := strings.TrimSuffix(name, ext)
	dot := strings.LastIndexByte(stem, '.')
	if dot < 0 {
		return false
	}

	hash := stem[dot+1:]
	// Vite emits an eight-character base64url content hash before the extension
	if len(hash) != 8 {
		return false
	}
	for _, char := range hash {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}

	return true
}

func setPageSecurityHeaders(w http.ResponseWriter) {
	// Content-Security-Policy:
	//   default-src 'none'  — deny everything not explicitly allowed
	//   script-src 'self' 'wasm-unsafe-eval'
	//                       — JS only from same origin (Vite/SRI bundles) - 'wasm-unsafe-eval' is required for mlkem-wasm
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
