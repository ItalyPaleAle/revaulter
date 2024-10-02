package server

import (
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

// MiddlewareMaxBodySize is a middleware that limits the size of the request body
func (s *Server) MiddlewareMaxBodySize(c *gin.Context) {
	// Limit to 20KB
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 20<<10)
}

// MiddlewareLogger is a Gin middleware that uses slog for logging
func (s *Server) MiddlewareLogger(parentLog *slog.Logger) func(c *gin.Context) {
	return func(c *gin.Context) {
		method := c.Request.Method

		// Ensure the logger in the context has a request ID, then store it in the context
		reqId := c.GetString("request-id")
		log := parentLog.With(slog.String("id", reqId))
		c.Request = c.Request.WithContext(logging.LogToContext(c.Request.Context(), log))

		// Do not log OPTIONS requests
		if method == http.MethodOptions {
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
		if respSize < 0 {
			// If no data was written, respSize could be -1
			respSize = 0
		}

		// Get the logger and the appropriate error level
		var level slog.Level
		switch {
		case statusCode >= 200 && statusCode <= 399:
			level = slog.LevelInfo
		case statusCode >= 400 && statusCode <= 499:
			level = slog.LevelWarn
		default:
			level = slog.LevelError
		}

		// Check if we have a message
		msg := c.GetString("log-message")
		if msg == "" {
			msg = "HTTP Request"
		}

		// Check if we have an error
		if lastErr := c.Errors.Last(); lastErr != nil {
			// We'll pick the last error only
			log = log.With(slog.Any("error", lastErr.Err))

			// Set the message as request failed
			msg = "Failed request"
		}

		// Check if we want to mask something in the URL
		mask, ok := c.Get("log-mask")
		if ok {
			f, ok := mask.(func(string) string)
			if ok && f != nil {
				path = f(path)
			}
		}

		// Emit the log
		log.LogAttrs(c.Request.Context(), level, msg,
			slog.Int("status", statusCode),
			slog.String("method", method),
			slog.String("path", path),
			slog.String("client", clientIP),
			slog.Float64("duration", float64(duration.Microseconds())/1000),
			slog.Int("size", respSize),
		)
	}
}

// MiddlewareCountMetrics is a Gin middleware that records requests served by the server
func (s *Server) MiddlewareCountMetrics(c *gin.Context) {
	if s.metrics == nil {
		// Process the request and do nothing
		c.Next()
		return
	}

	// Route name is "<method> <path>", where "path" is the path defined in the router
	route := c.Request.Method + " " + c.FullPath()
	start := time.Now()

	// Process the route
	c.Next()

	// Emit the metric
	s.metrics.RecordServerRequest(route, c.Writer.Status(), time.Since(start))
}

// MiddlewareLoggerMask returns a Gin middleware that adds the "log-mask" to mask the path using a regular expression
func (s *Server) MiddlewareLoggerMask(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("log-mask", func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}
