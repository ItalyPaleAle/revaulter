package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/ratelimit"

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
		v := c.GetHeader(headerName)
		if v != "" {
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

// MiddlewareNoCache is a middleware that disables caching on clients and CDNs
func (s *Server) MiddlewareNoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
}

// MiddlewareRateLimit returns a Gin middleware that enforces a global request-per-second limit using a leaky-bucket algorithm.
// Requests that exceed the limit receive HTTP 429 Too Many Requests.
func MiddlewareRateLimit(rps int) gin.HandlerFunc {
	limiter := ratelimit.New(rps, ratelimit.WithoutSlack)
	return func(c *gin.Context) {
		limiter.Take()
		c.Next()
	}
}
