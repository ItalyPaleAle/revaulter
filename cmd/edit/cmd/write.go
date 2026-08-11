package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/cliutil"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// allowEmptyFlag permits replacing the contents of a file with nothing
var allowEmptyFlag bool

func newWriteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "write [flags] FILE",
		Short: "Encrypt the contents of stdin into a file",
		Long: `Reads the new contents of a file from stdin, encrypts them, and writes them back.

This is the counterpart of "cat", for encrypting a file without opening an editor: it makes it possible to encrypt a file that already exists, to update one from a script, or to edit one with an editor this command cannot launch itself.

If the file does not exist, a new random encryption key is generated and wrapped with Revaulter. If it does exist, its own key is unwrapped and reused, so the contents are replaced without changing the key.`,
		Example: `  # Encrypt an existing cleartext file, then remove the original
  revaulter-edit write secrets.txt.enc < secrets.txt

  # Read a file, edit it with any editor, and write it back
  revaulter-edit cat secrets.txt > /tmp/secrets
  "$EDITOR" /tmp/secrets
  revaulter-edit write secrets.txt < /tmp/secrets`,
		Args: cobra.ArbitraryArgs,
		RunE: runWrite,
	}

	cmd.Flags().BoolVar(&allowEmptyFlag, "allow-empty", false, "Allow replacing the contents of the file with nothing")

	return cmd
}

func runWrite(cmd *cobra.Command, args []string) error {
	// Check the arguments before reading anything, so an invocation that cannot work fails right away
	_, err := fileArg(args)
	if err != nil {
		return err
	}

	log := logging.LogFromContext(cmd.Context())

	// Read the contents before contacting the server, so a failure here does not waste an approval
	plaintext, err := readContents(log)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 && !allowEmptyFlag {
		return errors.New("refusing to write empty contents: pass --allow-empty if that is intended")
	}

	file, _, err := openForCommand(cmd, args, true)
	if err != nil {
		return err
	}

	err = file.Save(plaintext)
	if err != nil {
		return err
	}

	log.Info("Saved the encrypted file", slog.String("file", file.Path), slog.Int("bytes", len(plaintext)))

	return nil
}

// readContents reads the new contents of the file from stdin
func readContents(log *slog.Logger) ([]byte, error) {
	// Nothing is piped in when stdin is a terminal, so say what the command is waiting for rather than looking like it hung
	if cliutil.IsTerminal(os.Stdin) {
		log.Info("Reading the new contents of the file from stdin, until the end of the input (Ctrl-D)")
	}

	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read the contents from stdin: %w", err)
	}

	return plaintext, nil
}
