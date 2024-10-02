package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/italypaleale/revaulter/pkg/utils"
)

// Type for a flag that accepts a base64-encoded string
// Implements pflag.Value and json.Marshaler
type stringValue string

func (d *stringValue) Set(s string) error {
	// Ensure it's valid base64
	data, err := utils.DecodeBase64String(s)
	if err != nil {
		return fmt.Errorf("invalid base64-encoded input: %w", err)
	}

	// Re-encode to base64
	*d = stringValue(base64.RawStdEncoding.EncodeToString(data))
	return err
}

func (d *stringValue) Type() string {
	return "base64-encoded string"
}

func (d *stringValue) String() string {
	return string(*d)
}

// Implements json.Marshaler
func (d *stringValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(*d))
}

// Type for a flag that accepts a Go duration or a number of seconds
// Implements pflag.Value and json.Marshaler
type durationValue time.Duration

func (d *durationValue) Set(s string) error {
	// First, check if the value is a number, and assume that's a value in seconds
	seconds, err := strconv.Atoi(s)
	if err == nil {
		*d = durationValue(time.Duration(seconds) * time.Second)
		return nil
	}

	// Try parsing as Go duration
	v, err := time.ParseDuration(s)
	*d = durationValue(v)
	return err
}

func (d *durationValue) Type() string {
	return "duration"
}

func (d *durationValue) String() string {
	if d.isEmpty() {
		return ""
	}

	return (*time.Duration)(d).String()
}

// Implements json.Marshaler
func (d *durationValue) MarshalJSON() ([]byte, error) {
	if d.isEmpty() {
		return []byte(`null`), nil
	}

	return json.Marshal(time.Duration(*d))
}

func (d *durationValue) isEmpty() bool {
	return d == nil || time.Duration(*d) == 0
}
