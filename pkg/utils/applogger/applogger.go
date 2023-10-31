package applogger

import (
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/italypaleale/revaulter/pkg/config"
)

// Logger is used to write custom logs
type Logger struct {
	// Optional "app" field to add
	App string

	log zerolog.Logger
}

// NewLogger returns a new Logger object
func NewLogger(app string, out io.Writer) *Logger {
	a := &Logger{
		App: app,
	}
	if out == nil {
		out = gin.DefaultWriter
	}
	a.InitWithWriter(out)
	return a
}

// InitWithWriter inits the object with a specified output writer
func (a *Logger) InitWithWriter(out io.Writer) {
	lctx := zerolog.New(out).With().Timestamp()
	if a.App != "" {
		lctx = lctx.Str("app", a.App)
	}
	a.log = lctx.Logger()
}

// SetLogLevel updates the logger to set
func (a *Logger) SetLogLevel(level zerolog.Level) {
	a.log = a.log.Level(level)
}

// Log returns a zerolog.Logger with data to append for custom logging
func (a *Logger) Log(c *gin.Context) *zerolog.Logger {
	// Add parameters
	lctx := a.log.With().
		Str("reqId", c.GetString("request-id"))

	// Return the logger
	logger := lctx.Logger()
	return &logger
}

// Raw returns the raw zerolog.Logger instances
func (a *Logger) Raw() *zerolog.Logger {
	return &a.log
}

// LoggerMiddleware is a Gin middleware that uses zerlog for logging
func (a *Logger) LoggerMiddleware(c *gin.Context) {
	method := c.Request.Method

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
	reqId := c.GetString("request-id")

	// Get the logger and the appropriate error level
	var event *zerolog.Event
	switch {
	case statusCode >= 200 && statusCode <= 399:
		event = a.log.Info() //nolint:zerologlint
	case statusCode >= 400 && statusCode <= 499:
		event = a.log.Warn() //nolint:zerologlint
	default:
		event = a.log.Error() //nolint:zerologlint
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
func (a *Logger) LoggerMaskMiddleware(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("log-mask", func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}
