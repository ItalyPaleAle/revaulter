package buildinfo

import (
	"fmt"

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
)

// Set during initialization
var BuildDescription string

func init() {
	if BuildId != "" && BuildDate != "" && CommitHash != "" {
		BuildDescription = fmt.Sprintf("%s, %s (%s)", BuildId, BuildDate, CommitHash)
	} else {
		BuildDescription = "null"
	}

	if !utils.IsTruthy(Production) {
		BuildDescription += " (non-production)"
	}
}
