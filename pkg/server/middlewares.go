package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
)

// MiddlewareMaxBodySize is a middleware that limits the size of the request body
func (s *Server) MiddlewareMaxBodySize(maxSize int64) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
	}
}

// MiddlewareRequestId is a middleware that generates a unique request ID for each request
func (s *Server) MiddlewareRequestId(c *gin.Context) {
	// Get the request ID
	reqId, err := s.getRequestID(c)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Set in the context and response header
	c.Set("request-id", reqId)
	c.Header("x-request-id", reqId)

	// Add the request ID to the span if tracing is enabled
	if s.tracer != nil {
		span := trace.SpanFromContext(c.Request.Context())
		span.SetAttributes(attribute.String(buildinfo.AppName+".request_id", reqId))
	}
}

func (s *Server) getRequestID(c *gin.Context) (string, error) {
	// Check if we have a trusted request ID header and it has a value
	headerName := config.Get().TrustedRequestIdHeader
	if headerName != "" {
		v := strings.TrimSpace(c.GetHeader(headerName))
		if validateTrustedRequestID(v) {
			return v, nil
		}
	}

	// If we get here, we have no request ID found in headers, so let's generate a new UUID
	reqUuid, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate request ID UUID: %w", err)
	}

	v := reqUuid.String()
	return v, nil
}

// validateTrustedRequestID validates that the request ID header matches `[A-Za-z0-9._:-]{1,128}`
func validateTrustedRequestID(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}

	for _, ch := range v {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}

		switch ch {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}

	return true
}

// MiddlewareNoCache is a middleware that disables caching on clients and CDNs
func (s *Server) MiddlewareNoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	c.Header("Pragma", "no-cache")
}

// MiddlewareCSRF offers CSRF protection for browser-facing endpoints
// This rejects cross-origin requests on state-changing methods (POST, PUT, DELETE, etc) by checking the Sec-Fetch-Site and Origin headers
// Requests with a Bearer-scheme Authorization header are exempt because bearer tokens cannot be auto-attached by a browser, making them immune to CSRF
func (s *Server) MiddlewareCSRF() func(c *gin.Context) {
	cop := http.NewCrossOriginProtection()
	return func(c *gin.Context) {
		// Bearer-authenticated requests are immune to CSRF by definition
		// Other schemes (Basic, Digest, ...) can be auto-attached by browsers and must not be exempted
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && strings.ToLower(authHeader[:7]) == "bearer " {
			c.Next()
			return
		}

		cop.
			Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.Next()
			})).
			ServeHTTP(c.Writer, c.Request)

		// If CrossOriginProtection rejected the request, abort the Gin chain
		if c.Writer.Status() == http.StatusForbidden {
			c.Abort()
			return
		}
	}
}
