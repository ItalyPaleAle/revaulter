package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/italypaleale/revaulter/pkg/config"
)

// RequestIdMiddleware is a middleware that generates a unique request ID for each request
func (s *Server) RequestIdMiddleware(c *gin.Context) {
	// Check if we have a trusted request ID header and it has a value
	headerName := config.Get().TrustedRequestIdHeader
	if headerName != "" {
		v := c.GetHeader(headerName)
		if v != "" {
			c.Set("request-id", v)
			c.Header("x-request-id", v)
			return
		}
	}

	// If we get here, we have no request ID found in headers, so let's generate a new UUID
	reqUuid, err := uuid.NewRandom()
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to generate request ID UUID: %w", err))
		return
	}

	v := reqUuid.String()
	c.Set("request-id", v)
	c.Header("x-request-id", v)
}
