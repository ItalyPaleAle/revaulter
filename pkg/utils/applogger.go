package utils

import (
	"io"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// AppLogger is used to write custom logs
type AppLogger struct {
	// Optional "app" field to add
	App string

	log *zerolog.Logger
}

// Init the object with the default writer for gin
func (a *AppLogger) Init() error {
	return a.InitWithWriter(gin.DefaultWriter)
}

// InitWithWriter inits the object with a specified output writer
func (a *AppLogger) InitWithWriter(out io.Writer) error {
	lctx := zerolog.New(out).With().Timestamp()
	if a.App != "" {
		lctx = lctx.Str("app", a.App)
	}
	logger := lctx.Logger()
	a.log = &logger
	return nil
}

// Log returns a zerolog.Logger with data to append for custom logging
func (a *AppLogger) Log(c *gin.Context) *zerolog.Logger {
	// Add parameters
	lctx := a.log.With().
		Str("reqId", c.GetString("request-id"))

	// Return the logger
	logger := lctx.Logger()
	return &logger
}

// Raw returns the raw zerolog.Logger instances
func (a *AppLogger) Raw() *zerolog.Logger {
	return a.log
}

// LoggerMiddleware is a Gin middleware that uses zerlog for logging
func (a *AppLogger) LoggerMiddleware(c *gin.Context) {
	method := c.Request.Method

	// Do not log OPTIONS requests
	if method == "OPTIONS" {
		c.Next()
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
	reqId := c.GetString("request-id")

	// Get the logger and the appropriate error level
	var event *zerolog.Event
	if statusCode >= 200 && statusCode <= 399 {
		event = a.log.Info()
	} else if statusCode >= 400 && statusCode <= 499 {
		event = a.log.Warn()
	} else {
		event = a.log.Error()
	}

	// Check if we have an error
	if len(c.Errors) > 0 {
		// We'll pick the last error only
		event = event.Str("error", c.Errors.Last().Error())
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
		Str("reqId", reqId).
		Int("status", statusCode).
		Str("method", method).
		Str("path", path).
		Str("clientIp", clientIP).
		Dur("duration", duration).
		Int("respSize", respSize).
		Msg(msg)
}

// LoggerMaskMiddleware returns a Gin middleware that adds the "log-mask" to mask the path using a regular expression
func (a *AppLogger) LoggerMaskMiddleware(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("log-mask", func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}
