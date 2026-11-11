package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckServerVersion(t *testing.T) {
	tests := []struct {
		name          string
		serverVersion string
		cliVersion    string
		minVersion    string
		wantWarning   bool
		wantErr       string
	}{
		{name: "same version as the CLI", serverVersion: "2.9.0", cliVersion: "2.9.0"},
		{name: "newer than the CLI", serverVersion: "2.10.0", cliVersion: "2.9.0"},
		{name: "older than the CLI", serverVersion: "2.8.1", cliVersion: "2.9.0", wantWarning: true},
		{name: "versions are compared numerically, not as strings", serverVersion: "2.9.0", cliVersion: "2.10.0", wantWarning: true},
		{name: "prerelease is older than the release", serverVersion: "2.9.0-beta.1", cliVersion: "2.9.0", wantWarning: true},
		{name: "leading v is accepted", serverVersion: "v2.8.1", cliVersion: "2.9.0", wantWarning: true},
		{name: "non-release CLI never warns", serverVersion: "2.8.1", cliVersion: "canary"},
		{name: "non-release server never warns", serverVersion: "edge", cliVersion: "2.9.0"},
		{name: "at the minimum version", serverVersion: "2.9.0", cliVersion: "2.9.0", minVersion: "2.9.0"},
		{name: "above the minimum version", serverVersion: "2.9.1", cliVersion: "2.9.1", minVersion: "v2.9"},
		{name: "below the minimum version", serverVersion: "2.8.1", cliVersion: "2.9.0", minVersion: "2.9.0", wantErr: "older than --min-version 2.9.0"},
		{name: "below the minimum version with a non-release CLI", serverVersion: "2.8.1", cliVersion: "canary", minVersion: "2.9.0", wantErr: "older than --min-version 2.9.0"},
		{name: "non-release server with a minimum version", serverVersion: "edge", cliVersion: "2.9.0", minVersion: "2.9.0", wantErr: "isn't a release version"},
		{name: "invalid minimum version", serverVersion: "2.9.0", cliVersion: "2.9.0", minVersion: "latest", wantErr: "not a valid release version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning, err := checkServerVersion(tt.serverVersion, tt.cliVersion, tt.minVersion)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			if tt.wantWarning {
				assert.Contains(t, warning, "older than this CLI")
			} else {
				assert.Empty(t, warning)
			}
		})
	}
}
