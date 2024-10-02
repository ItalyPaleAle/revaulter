package cmd

import (
	"fmt"
	"os"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "version",
			Short: "Display the version of the CLI",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintf(os.Stdout, "revaulter-cli\nVersion: %s\nBuild: %s\n", buildinfo.AppVersion, buildinfo.BuildDescription)
			},
		},
	)
}
