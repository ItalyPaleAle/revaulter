package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/server"
	"github.com/italypaleale/revaulter/pkg/utils"
)

var appLogger *utils.AppLogger

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the app logger object
	appLogger = utils.NewAppLogger("revaulter", os.Stdout)

	// Load config
	err := loadConfig()
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal()
		} else {
			appLogger.Raw().Fatal().
				Err(err).
				Msg("Failed to load configuration")
		}
	}

	// Init the webhook object
	webhook := utils.NewWebhook(appLogger)

	// Create the Server object
	srv, err := server.NewServer(appLogger, webhook)
	if err != nil {
		appLogger.Raw().Fatal().
			Err(err).
			Msg("Cannot initialize the server")
		return
	}

	// Listen for SIGTERM and SIGINT in background to stop the context
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

		<-ch
		appLogger.Raw().Info().Msg("Received interrupt signal. Shutting down…")
		cancel()

		// If we get another interrupt signal while we're shutting down, terminate immediately
		<-ch
		appLogger.Raw().Fatal().Msg("Received a second interrupt signal. Forcing a shutdown…")
	}()

	// Start the server in background and block until the server is shut down (gracefully)
	err = srv.Run(ctx)
	if err != nil {
		appLogger.Raw().Fatal().
			Err(err).
			Msg("Cannot start the server")
		return
	}
}
