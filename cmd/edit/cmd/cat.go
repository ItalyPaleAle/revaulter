package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

func newCatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cat [flags] FILE",
		Short: "Print the contents of an encrypted file",
		Long: `Decrypts a file and writes its contents to stdout.

Unwrapping the file's encryption key requires approval in the browser, just like editing it.
Logs are written to stderr, so the output can be piped into other commands.`,
		Args: cobra.ArbitraryArgs,
		RunE: runCat,
	}
}

func runCat(cmd *cobra.Command, args []string) error {
	_, plaintext, err := openForCommand(cmd, args, false)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(plaintext)
	return err
}
