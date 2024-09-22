package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/client"
	"github.com/italypaleale/revaulter/pkg/config"
)

//go:generate ../../client/build.sh

const staticBaseDir = "dist"

func (s *Server) serveClient() func(c *gin.Context) {
	// Option used during development to proxy to another server (such as a dev server)
	clientProxyServer := config.Get().Dev.ClientProxyServer

	if clientProxyServer == "" {
		return func(c *gin.Context) {
			if !prepareStaticResponse(c) {
				return
			}

			// Serve the request from the embedded FS
			serveStaticFiles(c, c.Request.URL.Path, client.StaticFS)
		}
	}

	u, err := url.Parse(clientProxyServer)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse value for 'dev.clientProxyServer': %v", err))
	}
	proxy := proxyStaticFilesFunc(u)
	return func(c *gin.Context) {
		if !prepareStaticResponse(c) {
			return
		}

		// Serve the request from the proxy
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// Invoked before serving static files from embedded FS or proxy
func prepareStaticResponse(c *gin.Context) (ok bool) {
	// Only respond to GET requests
	if c.Request.Method != "GET" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Not found"))
		return false
	}

	// If the request is for "/" or for "/index.html", check here if the user has a cookie (but don't validate it here)
	// If there's no cookie, redirect to the auth page right away and save loading the client app
	path := strings.TrimPrefix(c.Request.URL.Path, "/")
	if path == "" || path == "index.html" {
		v, err := c.Cookie(atCookieName)
		if err != nil || v == "" {
			c.Header("Location", "/auth/signin")
			c.Status(http.StatusFound)
			return false
		}
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

	// File should implement io.Seeker when it's not a directory
	fseek, ok := f.(io.ReadSeekCloser)
	if !ok {
		AbortWithErrorJSON(c, fmt.Errorf("file %s does not implement io.ReadSeekCloser", stat.Name()))
		return
	}
	http.ServeContent(c.Writer, c.Request, stat.Name(), stat.ModTime(), fseek)
}

// Returns a proxy that serves static files proxying from another server
func proxyStaticFilesFunc(upstream *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = func(req *http.Request) {
		req.Host = upstream.Host
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
	}
	return proxy
}
