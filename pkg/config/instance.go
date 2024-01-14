package config

import (
	"time"
)

var config *Config

func init() {
	// Set the default config at startup
	config = GetDefaultConfig()
}

// Get returns the singleton instance
func Get() *Config {
	return config
}

// GetDefaultConfig returns the default configuration.
func GetDefaultConfig() *Config {
	return &Config{
		LogLevel:            "info",
		Port:                8080,
		Bind:                "0.0.0.0",
		MetricsPort:         2112,
		MetricsBind:         "0.0.0.0",
		SessionTimeout:      5 * time.Minute,
		RequestTimeout:      5 * time.Minute,
		OmitHealthCheckLogs: true,
	}
}
