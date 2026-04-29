package buildinfo

import (
	"fmt"
	"time"

	"github.com/italypaleale/revaulter/pkg/utils"
)

// These variables will be set at build time
var (
	AppName         string = "revaulter"
	AppVersion      string = "canary"
	BuildId         string
	CommitHash      string
	BuildDate       string
	Production      string
	ConfigEnvPrefix string = "REVAULTER_"

	// RepoURL is the canonical source repo for this build, set to the GitHub URL at build time
	// Defaults to a local/dev placeholder
	RepoURL string = "dev.local"
	// SigningRefPattern is the regex fragment for refs accepted by integrity verification
	// Release builds set this at build time to match the refs the release workflow is allowed to sign from
	// Local/dev builds default to tag refs only
	SigningRefPattern string = "tags/v.+"
)

// Set during initialization
var (
	BuildDescription string
	start            time.Time
)

func init() {
	start = time.Now()

	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}

	if !utils.IsTruthy(Production) {
		BuildDescription += " (non-production)"
	}
}

// GetBuildDate returns the binary's build date (as set at build time)
// If the date is empty or not correctly-formatted, returns the time the application was started
func GetBuildDate() time.Time {
	if BuildDate == "" {
		return start
	}

	d, err := time.Parse(time.RFC3339, BuildDate)
	if err != nil {
		return start
	}

	return d
}
