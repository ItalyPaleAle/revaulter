package main

import (
	"context"
	"errors"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/server"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/signals"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the logger and set it in the context
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "revaulter").
		Str("version", buildinfo.AppVersion).
		Logger()
	ctx := log.WithContext(context.Background())

	log.Info().
		Str("build", buildinfo.BuildDescription).
		Msg("Starting Revaulter")

	// Load config
	err := loadConfig(&log)
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal(&log)
		} else {
			log.Fatal().Err(err).Msg("Failed to load configuration")
		}
	}

	// Init the webhook object
	webhook := webhook.NewWebhook()

	// Create the Server object
	srv, err := server.NewServer(&log, webhook)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot initialize the server")
		return
	}

	// Get a context that is canceled when the application receives a termination signal
	ctx = signals.SignalContext(ctx)

	// Run the service
	runner := utils.NewServiceRunner(srv.Run)
	err = runner.Run(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to run service")
		return
	}
}
