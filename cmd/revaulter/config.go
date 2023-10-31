package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/configloader"
)

func loadConfig() error {
	const envPrefix = "REVAULTER_"

	// Get the path to the config.yaml
	// First, try with the REVAULTER_CONFIG env var
	configFile := os.Getenv(envPrefix + "CONFIG")
	if configFile != "" {
		exists, _ := utils.FileExists(configFile)
		if !exists {
			return newLoadConfigError("Environmental variable "+envPrefix+"CONFIG points to a file that does not exist", "Error loading config file")
		}
	} else {
		// Look in the default paths
		configFile = findConfigFile("config.yaml", ".", "~/.revaulter", "/etc/revaulter")
		if configFile == "" {
			// Ok, if you really, really want to use ".yml"....
			configFile = findConfigFile("config.yml", ".", "~/.revaulter", "/etc/revaulter")
		}
	}

	// Load the configuration
	// Note that configFile can be empty, if none was found (we can still use env vars)
	cfg := config.Get()
	err := configloader.Load(cfg, configloader.LoadOptions{
		FilePath:                 configFile,
		EnvPrefix:                envPrefix,
		IgnoreZeroValuesInConfig: true,
	})
	if err != nil {
		return newLoadConfigError(err, "Error loading config file")
	}
	cfg.SetLoadedConfigPath(configFile)

	// Process the configuration
	return processConfig(cfg)
}

func findConfigFile(fileName string, searchPaths ...string) string {
	for _, path := range searchPaths {
		if path == "" {
			continue
		}

		p, _ := homedir.Expand(path)
		if p != "" {
			path = p
		}

		search := filepath.Join(path, fileName)
		exists, _ := utils.FileExists(search)
		if exists {
			return search
		}
	}

	return ""
}

// Processes the configuration
func processConfig(cfg *config.Config) (err error) {
	// Log level
	err = setLogLevel(cfg)
	if err != nil {
		return err
	}

	// Check required variables
	err = cfg.Validate()
	if err != nil {
		return err
	}

	// Ensures the token signing key is present
	err = cfg.SetTokenSigningKey(appLogger.Raw())
	if err != nil {
		return err
	}

	// Set the cookie keys
	err = cfg.SetCookieKeys(appLogger.Raw())
	if err != nil {
		return err
	}

	return nil
}

// Sets the log level based on the configuration
func setLogLevel(cfg *config.Config) error {
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		appLogger.SetLogLevel(zerolog.DebugLevel)
	case "", "info": // Also default log level
		appLogger.SetLogLevel(zerolog.InfoLevel)
	case "warn":
		appLogger.SetLogLevel(zerolog.WarnLevel)
	case "error":
		appLogger.SetLogLevel(zerolog.ErrorLevel)
	default:
		return newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}
	return nil
}

// Error returned by loadConfig
type loadConfigError struct {
	err string
	msg string
}

// newLoadConfigError returns a new loadConfigError.
// The err argument can be a string or an error.
func newLoadConfigError(err any, msg string) *loadConfigError {
	return &loadConfigError{
		err: fmt.Sprintf("%v", err),
		msg: msg,
	}
}

// Error implements the error interface
func (e loadConfigError) Error() string {
	return e.err + ": " + e.msg
}

// LogFatal causes a fatal log
func (e loadConfigError) LogFatal() {
	appLogger.Raw().Fatal().
		Str("error", e.err).
		Msg(e.msg)
}
