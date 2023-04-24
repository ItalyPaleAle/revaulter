package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/unlocker/pkg/server"
	"github.com/italypaleale/unlocker/pkg/utils"
)

var appLogger *utils.AppLogger

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the app logger object
	var err error
	appLogger, err = utils.NewAppLogger("unlocker", os.Stderr)
	if err != nil {
		panic(err)
	}

	// Load config
	err = loadConfig()
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal()
		} else {
			appLogger.Raw().Fatal().
				AnErr("error", err).
				Msg("Failed to load configuration")
		}
	}

	// Create the Server object
	srv, err := server.NewServer(appLogger)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
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
	err = srv.Start(ctx)
	if err != nil {
		appLogger.Raw().Fatal().
			AnErr("error", err).
			Msg("Cannot start the server")
		return
	}
}
