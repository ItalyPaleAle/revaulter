package server

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/actors"
)

// newRateLimitMiddleware registers a rate limiter on the Francis host, and returns a middleware that applies it by client IP
func (s *Server) newRateLimitMiddleware(name string, rate int, per time.Duration) (gin.HandlerFunc, error) {
	rl, err := s.actors.NewRateLimiter(name, rate, per)
	if err != nil {
		return nil, err
	}

	return MiddlewareRateLimit(rl), nil
}

// MiddlewareRateLimit returns a Gin middleware that enforces a per-client-IP rate limit
// Requests that exceed the limit receive HTTP 429 Too Many Requests, with a Retry-After header
// If the limit can't be checked, the request is allowed
func MiddlewareRateLimit(rl *actors.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if clientIP == "" {
			clientIP = c.RemoteIP()
		}

		allowed, retryAfter := rl.Allow(c.Request.Context(), clientIP)
		if !allowed {
			setRetryAfter(c, retryAfter)
			AbortWithErrorJSON(c, NewResponseError(http.StatusTooManyRequests, "Too many requests; please retry later"))
			return
		}

		c.Next()
	}
}

// setRetryAfter sets the Retry-After header, in whole seconds rounded up
func setRetryAfter(c *gin.Context, retryAfter time.Duration) {
	seconds := max(int(math.Ceil(retryAfter.Seconds())), 1)
	c.Header("Retry-After", strconv.Itoa(seconds))
}
