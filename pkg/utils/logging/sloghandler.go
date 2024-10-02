package logging

import (
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

func SlogHandler(logAsJSON bool, level slog.Leveler, dest io.Writer) slog.Handler {
	switch {
	case logAsJSON:
		// Log as JSON if configured
		return slog.NewJSONHandler(dest, &slog.HandlerOptions{
			Level: level,
		})
	case isatty.IsTerminal(os.Stdout.Fd()):
		// Enable colors if we have a TTY
		return tint.NewHandler(dest, &tint.Options{
			Level:      level,
			TimeFormat: time.StampMilli,
		})
	default:
		return slog.NewTextHandler(dest, &slog.HandlerOptions{
			Level: level,
		})
	}
}
