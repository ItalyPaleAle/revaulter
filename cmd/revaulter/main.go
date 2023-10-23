package main

import (
	"errors"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/server"
	"github.com/italypaleale/revaulter/pkg/utils"
)

var appLogger *utils.AppLogger

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the app logger object
	appLogger = utils.NewAppLogger("revaulter", os.Stdout)

	appLogger.Raw().Info().
		Str("version", buildinfo.AppVersion).
		Str("build", buildinfo.BuildDescription).
		Msg("Starting Revaulter")

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

	// Get a context that is canceled when the application receives a termination signal
	ctx := utils.SignalContext(appLogger)

	// Run the service
	runner := utils.NewServiceRunner(srv.Run)
	err = runner.Run(ctx)
	if err != nil {
		appLogger.Raw().Fatal().
			Err(err).
			Msg("Failed to run service")
		return
	}
}
