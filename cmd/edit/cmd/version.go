package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/buildinfo"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display the version of revaulter-edit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "revaulter-edit\nVersion: %s\nBuild: %s\n", buildinfo.AppVersion, buildinfo.BuildDescription)
		},
	}
}
