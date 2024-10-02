package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

var (
	rootCmd = &cobra.Command{
		Use:          "revaulter-cli",
		Short:        "A CLI for interacting with Revaulter",
		Long:         `revaulter-cli helps interacting with Revaulter servers, performing operations on keys stored on Azure Key Vault, including: key wrapping and unwrapping, data encryption and decryption, computing and verifying digital signatures`,
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Enable debug logging if the verbose flag is set
			if pf.Verbose {
				pf.logLevel.Set(slog.LevelDebug)
			}
		},
	}
	pf persistentFlags
)

type persistentFlags struct {
	Verbose bool

	logLevel *slog.LevelVar
}

func init() {
	pf.logLevel = &slog.LevelVar{}
	pf.logLevel.Set(slog.LevelInfo)

	// Set persistent flags
	rootCmd.PersistentFlags().BoolVarP(&pf.Verbose, "verbose", "V", false, "Show debug-level logs")
}

// Run executes the root command
func Run() error {
	// Get the logger
	// Logs are printed to stderr
	log := slog.New(logging.SlogHandler(false, pf.logLevel, os.Stderr))

	// Create a context with the logger built-in
	ctx := logging.LogToContext(context.Background(), log)

	return rootCmd.ExecuteContext(ctx)
}
