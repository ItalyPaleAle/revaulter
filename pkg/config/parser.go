package config

import (
	"fmt"
	"maps"
	"os"
	"reflect"

	env "github.com/caarlos0/env/v9"
	"github.com/mitchellh/mapstructure"
	yaml "gopkg.in/yaml.v3"
)

// Load the configuration from a file and from the environment
func (c *Config) Load(filePath string, envPrefix string, ignoreZeroValuesInConfig bool) error {
	// First, load the config from the YAML into a map (if we have a file)
	if filePath != "" {
		m := map[string]any{}
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open config file '%s': %w", filePath, err)
		}
		defer f.Close()
		yamlDec := yaml.NewDecoder(f)
		yamlDec.KnownFields(true)
		err = yamlDec.Decode(&m)
		if err != nil {
			return fmt.Errorf("failed to decode config file '%s': %w", filePath, err)
		}

		// Ignore fields with zero value
		if ignoreZeroValuesInConfig {
			maps.DeleteFunc(m, func(s string, a any) bool {
				return reflect.ValueOf(a).IsZero()
			})
		}

		// Now apply the changes into the config object
		err = c.loadFromMap(m)
		if err != nil {
			return err
		}

		c.internal.configFileLoaded = filePath
	}

	// Next, update from env
	err := env.ParseWithOptions(c, env.Options{
		Prefix: envPrefix,
	})
	if err != nil {
		return fmt.Errorf("failed to parse config from env vars: %w", err)
	}

	return nil
}

// Internal function that applies the options from a map.
func (c *Config) loadFromMap(m map[string]any) error {
	mapDec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.TextUnmarshallerHookFunc(),
			// TODO: IsTruthy decoder
		),
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "yaml",
	})
	if err != nil {
		return fmt.Errorf("failed to init mapstructure decoder: %w", err)
	}
	err = mapDec.Decode(m)
	if err != nil {
		return fmt.Errorf("failed to decode from map: %w", err)
	}
	return nil
}
