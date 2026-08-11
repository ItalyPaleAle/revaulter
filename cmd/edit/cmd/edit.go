package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/cliutil"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

var (
	// editorFlag is the editor to launch, overriding VISUAL and EDITOR
	editorFlag string
	// noAutoWaitFlag disables adding the "--wait" flag to editors that return before the file has been edited
	noAutoWaitFlag bool
)

func bindEditFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&editorFlag, "editor", "", "Editor to launch (defaults to VISUAL, then EDITOR)")
	cmd.PersistentFlags().BoolVar(&noAutoWaitFlag, "no-auto-wait", false, "Do not add the '--wait' flag to editors that need it, such as 'code' and 'subl'")
}

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [flags] FILE",
		Short: "Edit an encrypted file in EDITOR",
		Long: `Decrypts a file and opens it in an editor.

Every time the editor saves, the contents are encrypted again and written back to the file.
The decrypted contents only exist in a temporary file that only the current user can read, and that is deleted when the editor exits.

If the file does not exist, a new random encryption key is generated and wrapped with Revaulter, and the file is created the first time the editor saves.

This is the default sub-command: running "revaulter-edit FILE" is the same as "revaulter-edit edit FILE".`,
		Args: cobra.ArbitraryArgs,
		RunE: runEdit,
	}

	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
	// Check the arguments and the editor before contacting the server: there is no point in asking the user to approve a request that cannot be used
	_, err := fileArg(args)
	if err != nil {
		return err
	}

	editor, err := resolveEditor(editorFlag)
	if err != nil {
		return err
	}

	file, plaintext, err := openForCommand(cmd, args, true)
	if err != nil {
		return err
	}

	session := &editSession{
		file:       file,
		log:        logging.LogFromContext(cmd.Context()),
		editor:     editor,
		noAutoWait: noAutoWaitFlag,
	}

	// The log only needs to be held back when it is being written to the terminal the editor is about to take over
	// When it is redirected to a file or a pipe, nothing is drawn on screen and the messages are more useful as they happen
	if cliutil.IsTerminal(os.Stderr) {
		session.logOutput = logOutput
	}

	return session.run(cmd.Context(), plaintext)
}
