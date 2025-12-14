package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"go.opentelemetry.io/contrib/exporters/autoexport"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	revaultermetrics "github.com/italypaleale/revaulter/pkg/metrics"
	"github.com/italypaleale/revaulter/pkg/server"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	err := loadConfig()
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}
	conf := config.Get()

	// Shutdown functions
	shutdownFns := make([]servicerunner.Service, 0, 3)

	// Get the logger and set it in the context
	log, shutdownFn, err := getLogger(context.Background(), conf)
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if shutdownFn != nil {
		shutdownFns = append(shutdownFns, shutdownFn)
	}

	// Validate the configuration
	err = processConfig(log, conf)
	if err != nil {
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting Revaulter", "build", buildinfo.BuildDescription)

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := logging.LogToContext(context.Background(), log)
	ctx = signals.SignalContext(ctx)

	// Init the webhook object
	webhook := webhook.NewWebhook()

	// Init metrics
	metrics, metricsShutdownFn, err := revaultermetrics.NewRevaulterMetrics(ctx, log)
	if err != nil {
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Get the trace exporter
	// If the env var OTEL_TRACES_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_TRACES_EXPORTER") == "" {
		os.Setenv("OTEL_TRACES_EXPORTER", "none")
	}
	traceExporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to init trace exporter", err)
		return
	}
	shutdownFns = append(shutdownFns, traceExporter.Shutdown)

	// Create the Server object
	srv, err := server.NewServer(server.NewServerOpts{
		Log:           log,
		Webhook:       webhook,
		Metrics:       metrics,
		TraceExporter: traceExporter,
	})
	if err != nil {
		slogkit.FatalError(log, "Cannot initialize the server", err)
		return
	}

	// Run the service
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(srv.Run).
		Run(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to run services", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = servicerunner.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
