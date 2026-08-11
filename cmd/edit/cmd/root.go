package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/utils/logging"
)

var (
	rootCmd = &cobra.Command{
		Use:   "revaulter-edit [flags] FILE",
		Short: "Read and edit local files encrypted with Revaulter",
		Long: `revaulter-edit encrypts local files with a key that is stored in Revaulter.

Files are saved in JWE format, encrypted with a random 256-bit key.
That key never exists in cleartext on disk: it is wrapped by Revaulter, and the information needed to unwrap it is kept in the JWE protected header.
Opening a file, to read it or to edit it, asks Revaulter to unwrap the key, which requires approval in the browser.

Running the command with a file and no sub-command opens it in EDITOR.`,
		Example: `  # Edit a file, creating it if it does not exist
  revaulter-edit --server https://revaulter.example.com --request-key "REQUEST_KEY" --key-label notes secrets.txt

  # Print the contents of a file
  revaulter-edit cat --server https://revaulter.example.com --request-key "REQUEST_KEY" secrets.txt`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Enable debug logging if the verbose flag is set
			if pf.Verbose {
				logLevel.Set(slog.LevelDebug)
			}
		},
		RunE: runEdit,
	}

	// pf carries the flags shared by every sub-command
	pf       commonFlags
	logLevel = &slog.LevelVar{}
	// logOutput is where the log is written, which the edit session pauses while the editor owns the terminal
	logOutput = newPausableWriter(os.Stderr)
)

func init() {
	logLevel.Set(slog.LevelInfo)

	pf.Bind(rootCmd)

	// The root command runs "edit", so it takes the same flags
	bindEditFlags(rootCmd)

	rootCmd.AddCommand(
		newEditCmd(),
		newCatCmd(),
		newWriteCmd(),
		newVersionCmd(),
	)
}

// Run executes the root command
func Run() bool {
	// Get the logger
	// Logs are printed to stderr, so the output of "cat" can be piped
	log := slog.New(logging.SlogHandler(false, logLevel, logOutput))
	slog.SetDefault(log)

	// Create a context with the logger built-in
	ctx := logging.LogToContext(context.Background(), log)

	// Run the command
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		log.Error(err.Error())
		return false
	}

	return true
}

// openForCommand validates the flags, connects to the Revaulter server, and opens the file the command was invoked with
func openForCommand(cmd *cobra.Command, args []string, create bool) (*encryptedFile, []byte, error) {
	path, err := fileArg(args)
	if err != nil {
		return nil, nil, err
	}

	err = pf.Validate()
	if err != nil {
		return nil, nil, err
	}

	log := logging.LogFromContext(cmd.Context())
	client, err := pf.newClient(log)
	if err != nil {
		return nil, nil, err
	}

	return openFile(cmd.Context(), log, &revaulterKeyWrapper{client: client}, openOptions{
		Path:      path,
		Server:    pf.Server,
		KeyLabel:  pf.KeyLabel,
		Algorithm: pf.Algorithm,
		Note:      requestNote(pf.Note, path),
		Create:    create,
	})
}
