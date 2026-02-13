package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	logGlobal "go.opentelemetry.io/otel/log/global"
	logSdk "go.opentelemetry.io/otel/sdk/log"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/configloader"
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

func getLogger(ctx context.Context, cfg *config.Config) (log *slog.Logger, shutdownFn func(ctx context.Context) error, err error) {
	// Get the level
	level, err := getLogLevel(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Create the handler
	var handler slog.Handler
	switch {
	case cfg.LogAsJSON:
		// Log as JSON if configured
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	case isatty.IsTerminal(os.Stdout.Fd()):
		// Enable colors if we have a TTY
		handler = tint.NewHandler(os.Stdout, &tint.Options{
			Level:      level,
			TimeFormat: time.StampMilli,
		})
	default:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	// Create a handler that sends logs to OTel too
	// We wrap the handler in a "fanout" handler that sends logs to both
	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// If the env var OTEL_LOGS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_LOGS_EXPORTER") == "" {
		os.Setenv("OTEL_LOGS_EXPORTER", "none")
	}
	exp, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry log exporter: %w", err)
	}

	// Create the logger provider
	provider := logSdk.NewLoggerProvider(
		logSdk.WithProcessor(
			logSdk.NewBatchProcessor(exp),
		),
		logSdk.WithResource(resource),
	)

	// Set the logger provider globally
	logGlobal.SetLoggerProvider(provider)

	// Wrap the handler in a "fanout" one
	handler = slog.NewMultiHandler(handler, otelslog.NewHandler(buildinfo.AppName, otelslog.WithLoggerProvider(provider)))

	// Return a function to invoke during shutdown
	shutdownFn = provider.Shutdown

	log = slog.New(handler).
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

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
	slogkit.FatalError(log, e.msg, errors.New(e.err))
}
