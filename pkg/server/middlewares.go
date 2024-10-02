package server

import (
	"crypto/subtle"
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

// RequestKeyMiddleware is a middleware that asserts that the Authorization header contains the shared requestKey
func (s *Server) RequestKeyMiddleware() gin.HandlerFunc {
	// Get the requestKey
	conf := config.Get().RequestKey
	if conf == "" {
		// No key, so allow everything
		return func(c *gin.Context) {}
	}
	confB := []byte(conf)

	// Return the middleware
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		// The "bearer" or "APIKey" prefixes are optional
		if len(authHeader) > 7 {
			prefix := strings.ToLower(authHeader[0:7])
			if prefix == "bearer " || prefix == "apikey " {
				authHeader = authHeader[7:]
			}
		}

		// Check if the key matches
		if subtle.ConstantTimeCompare(confB, []byte(authHeader)) == 0 {
			AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Invalid secret key in the Authorization header"))
			return
		}
	}
}
