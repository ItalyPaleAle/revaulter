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
		if validTrustedRequestID(v) {
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

// validTrustedRequestID validates that the request ID header matches `[A-Za-z0-9._:-]{1,128}`
func validTrustedRequestID(v string) bool {
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
	c.Header("Cache-Control", "no-cache")
}
