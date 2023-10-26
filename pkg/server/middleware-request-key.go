package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/config"
)

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
		// The "bearer" prefix is optional
		if len(authHeader) > 7 && strings.ToLower(authHeader[0:7]) == "bearer " {
			authHeader = authHeader[7:]
		}

		// Check if the key matches
		if subtle.ConstantTimeCompare(confB, []byte(authHeader)) == 0 {
			_ = c.Error(errors.New("invalid secret key in Authorization header"))
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse("Invalid secret key in the Authorization header"))
			return
		}
	}
}
