package server

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/httprate"
)

type clientIPCtxKey struct{}

// MiddlewareRateLimit returns a Gin middleware that enforces a per-client-IP request-per-second limit
// Requests that exceed the limit receive HTTP 429 Too Many Requests
func MiddlewareRateLimit(rpm int) gin.HandlerFunc {
	rl := httprate.NewRateLimiter(rpm, time.Minute)
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if clientIP == "" {
			clientIP = c.RemoteIP()
		}

		onLimit := rl.RespondOnLimit(c.Writer, c.Request, clientIP)
		if onLimit {
			c.Abort()
			return
		}

		c.Next()
	}
}
