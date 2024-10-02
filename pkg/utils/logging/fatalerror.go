package logging

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"time"
)

// FatalError emits a log at the error level and causes the application to exit
func FatalError(log *slog.Logger, message string, err error) {
	// Emit the log only if the level is enabled
	if !log.Enabled(context.Background(), slog.LevelError) {
		// Exit without a log
		os.Exit(1)
		return
	}

	// See https://pkg.go.dev/log/slog#example-package-Wrapping
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), slog.LevelError, message, pcs[0])
	r.AddAttrs(slog.String("error", err.Error()))
	_ = log.Handler().Handle(context.Background(), r)

	os.Exit(1)
}
