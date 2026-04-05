package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/ratelimit"
)

// MiddlewareRateLimit returns a Gin middleware that enforces a global
// request-per-second limit using a leaky-bucket algorithm.
// Requests that exceed the limit receive HTTP 429 Too Many Requests.
func MiddlewareRateLimit(rps int) gin.HandlerFunc {
	limiter := ratelimit.New(rps, ratelimit.WithoutSlack)
	return func(c *gin.Context) {
		limiter.Take()
		c.Next()
	}
}
