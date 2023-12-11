package server

import (
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/italypaleale/revaulter/pkg/config"
)

// LoggerMiddleware is a Gin middleware that uses zerlog for logging
func (s *Server) LoggerMiddleware(parentLog *zerolog.Logger) func(c *gin.Context) {
	return func(c *gin.Context) {
		method := c.Request.Method

		// Ensure the logger in the context has a request ID, then store it in the context
		reqId := c.GetString("request-id")
		log := parentLog.With().
			Str("reqId", reqId).
			Logger()
		c.Request = c.Request.WithContext(log.WithContext(c.Request.Context()))

		// Do not log OPTIONS requests
		if method == http.MethodOptions {
			return
		}

		// Omit logging /healthz calls if set
		if c.Request.URL.Path == "/healthz" && config.Get().OmitHealthCheckLogs {
			return
		}

		// Start time to measure latency (request duration)
		start := time.Now()
		path := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			path = path + "?" + c.Request.URL.RawQuery
		}

		// Process request
		c.Next()

		// Other fields to include
		duration := time.Since(start)
		clientIP := c.ClientIP()
		statusCode := c.Writer.Status()
		respSize := c.Writer.Size()

		// Get the logger and the appropriate error level
		var event *zerolog.Event
		switch {
		case statusCode >= 200 && statusCode <= 399:
			event = log.Info() //nolint:zerologlint
		case statusCode >= 400 && statusCode <= 499:
			event = log.Warn() //nolint:zerologlint
		default:
			event = log.Error() //nolint:zerologlint
		}

		// Check if we have an error
		if len(c.Errors) > 0 {
			// We'll pick the last error only
			event = event.Err(c.Errors.Last().Err)
		}

		// Check if we have a message
		msg := c.GetString("log-message")

		// Check if we want to mask something in the URL
		mask, ok := c.Get("log-mask")
		if ok {
			f, ok := mask.(func(string) string)
			if ok && f != nil {
				path = f(path)
			}
		}

		// Set parameters
		event.
			Int("status", statusCode).
			Str("method", method).
			Str("path", path).
			Str("clientIp", clientIP).
			Dur("duration", duration).
			Int("respSize", respSize).
			Msg(msg)
	}
}

// LoggerMaskMiddleware returns a Gin middleware that adds the "log-mask" to mask the path using a regular expression
func (s *Server) LoggerMaskMiddleware(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("log-mask", func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}
