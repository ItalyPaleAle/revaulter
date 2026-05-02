//go:build !unix

package cmd

import (
	"github.com/spf13/cobra"
)

// The ssh-agent command is only available on Unix systems
func newSshAgentCmd() *cobra.Command {
	return nil
}
