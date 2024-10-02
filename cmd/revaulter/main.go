package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	revaultermetrics "github.com/italypaleale/revaulter/pkg/metrics"
	"github.com/italypaleale/revaulter/pkg/server"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/utils/signals"
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
			logging.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}
	conf := config.Get()

	// Shutdown functions
	shutdownFns := make([]utils.Service, 0, 3)

	// Get the logger and set it in the context
	log, shutdownFn, err := getLogger(conf)
	if err != nil {
		logging.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if shutdownFn != nil {
		shutdownFns = append(shutdownFns, shutdownFn)
	}

	// Validate the configuration
	err = processConfig(log, conf)
	if err != nil {
		logging.FatalError(log, "Invalid configuration", err)
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
	var metrics *revaultermetrics.RevaulterMetrics
	if conf.EnableMetrics {
		metrics, shutdownFn, err = revaultermetrics.NewRevaulterMetrics(ctx, log)
		if err != nil {
			logging.FatalError(log, "Failed to init metrics", err)
			return
		}
		if shutdownFn != nil {
			shutdownFns = append(shutdownFns, shutdownFn)
		}
	}

	// Get the trace traceExporter if tracing is enabled
	var traceExporter sdkTrace.SpanExporter
	if conf.EnableTracing {
		traceExporter, err = conf.GetTraceExporter(ctx, log)
		if err != nil {
			logging.FatalError(log, "Failed to init trace exporter", err)
			return
		}

		shutdownFns = append(shutdownFns, traceExporter.Shutdown)
	}

	// Create the Server object
	srv, err := server.NewServer(server.NewServerOpts{
		Log:           log,
		Webhook:       webhook,
		Metrics:       metrics,
		TraceExporter: traceExporter,
	})
	if err != nil {
		logging.FatalError(log, "Cannot initialize the server", err)
		return
	}

	// Run the service
	// This call blocks until the context is canceled
	err = utils.
		NewServiceRunner(srv.Run).
		Run(ctx)
	if err != nil {
		logging.FatalError(log, "Failed to run services", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = utils.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
