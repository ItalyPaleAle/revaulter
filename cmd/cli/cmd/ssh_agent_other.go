//go:build !unix

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSshAgentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-agent",
		Short: "Run an SSH key agent that routes signing through Revaulter (Unix only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ssh-agent is only supported on Unix platforms")
		},
	}
}
