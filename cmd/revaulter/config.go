package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	logGlobal "go.opentelemetry.io/otel/log/global"
	logSdk "go.opentelemetry.io/otel/sdk/log"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/configloader"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

func loadConfig() error {
	// Get the path to the config.yaml
	// First, try with the REVAULTER_CONFIG env var
	configFile := os.Getenv(buildinfo.ConfigEnvPrefix + "CONFIG")
	if configFile != "" {
		exists, _ := utils.FileExists(configFile)
		if !exists {
			return newLoadConfigError("Environmental variable "+buildinfo.ConfigEnvPrefix+"CONFIG points to a file that does not exist", "Error loading config file")
		}
	} else {
		// Look in the default paths
		// We'll accept ".yml" and ".json" too (but still load it as a YAML)
		configFile = findConfigFiles(
			[]string{"config.yaml", "config.yml", "config.json"},
			[]string{".", "~/.revaulter", "/etc/revaulter"},
		)
	}

	// Load the configuration
	// Note that configFile can be empty, if none was found (we can still use env vars)
	cfg := config.Get()
	err := configloader.Load(cfg, configloader.LoadOptions{
		FilePath:                 configFile,
		EnvPrefix:                buildinfo.ConfigEnvPrefix,
		IgnoreZeroValuesInConfig: true,
	})
	if err != nil {
		return newLoadConfigError(err, "Error loading config file")
	}
	cfg.SetLoadedConfigPath(configFile)

	return nil
}

func getLogger(cfg *config.Config) (log *slog.Logger, shutdownFn func(ctx context.Context) error, err error) {
	// Get the level
	level, err := getLogLevel(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Check if we are sending logs to an OTel collector
	// We pass a background context here as the main context for the app isn't ready yet
	exp, expLogFn, err := cfg.GetLogsExporter(context.Background())
	if err != nil {
		// We don't use newLoadConfigError as this is not a loading error
		return nil, nil, fmt.Errorf("failed to get logger: %w", err)
	}

	// Create the handler
	handler := logging.SlogHandler(cfg.LogAsJSON, level, os.Stdout)

	// If we have an OpenTelemetry exporter, we need to create a handler that sends logs to OTel too
	// We wrap the handler in a "fanout" handler that sends logs to both
	if exp != nil {
		// Create the logger provider
		provider := logSdk.NewLoggerProvider(
			logSdk.WithProcessor(
				logSdk.NewBatchProcessor(exp),
			),
			logSdk.WithResource(cfg.GetOtelResource(buildinfo.AppName)),
		)

		// Set the logger provider globally
		logGlobal.SetLoggerProvider(provider)

		// Wrap the handler in a "fanout" one
		handler = logging.LogFanoutHandler{
			handler,
			otelslog.NewHandler(buildinfo.AppName, otelslog.WithLoggerProvider(provider)),
		}

		// Return a function to invoke during shutdown
		shutdownFn = provider.Shutdown
	}

	log = slog.New(handler).
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// If we have a function to emit a log from the exporter, invoke that now
	if exp != nil && expLogFn != nil {
		expLogFn(log)
	}
	return log, shutdownFn, nil
}

func findConfigFiles(fileNames []string, searchPaths []string) string {
	for _, name := range fileNames {
		path := findConfigFile(name, searchPaths)
		if path != "" {
			return path
		}
	}

	return ""
}

func findConfigFile(fileName string, searchPaths []string) string {
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
func processConfig(log *slog.Logger, cfg *config.Config) (err error) {
	// Check required variables
	err = cfg.Validate(log)
	if err != nil {
		return err
	}

	// Ensures the token signing key is present
	err = cfg.SetTokenSigningKey(log)
	if err != nil {
		return err
	}

	// Set the cookie keys
	err = cfg.SetCookieKeys(log)
	if err != nil {
		return err
	}

	return nil
}

func getLogLevel(cfg *config.Config) (slog.Level, error) {
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info": // Also default log level
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}
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
func (e loadConfigError) LogFatal(log *slog.Logger) {
	logging.FatalError(log, e.msg, errors.New(e.err))
}
