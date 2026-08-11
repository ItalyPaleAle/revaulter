// Package cliutil contains helpers shared by the Revaulter command-line tools
package cliutil

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/italypaleale/revaulter/internal/clientcore"
)

// stdinReader is shared by every prompt so input buffered by one prompt is still available to the next
var stdinReader = bufio.NewReader(os.Stdin)

// IsTerminal reports whether the file is attached to a terminal
func IsTerminal(f *os.File) bool {
	// File descriptors on supported platforms always fit in int
	return term.IsTerminal(int(f.Fd())) // #nosec G115
}

// IsInteractiveTerminal reports whether both stdin and stderr are attached to a terminal, which is what prompting the user requires
func IsInteractiveTerminal() bool {
	return IsTerminal(os.Stdin) && IsTerminal(os.Stderr)
}

// AnchorPrompt asks the user on stderr to accept a server's anchor fingerprint on first contact
// Callers must check IsInteractiveTerminal first: prompting without a TTY would block or read from a pipe
func AnchorPrompt(server string, fingerprint string) (bool, error) {
	fmt.Fprintf(os.Stderr, "First contact with %s.\n", server)
	fmt.Fprintf(os.Stderr, "Anchor fingerprint:\n%s\n", clientcore.FormatFingerprint(fingerprint, 2))
	fmt.Fprint(os.Stderr, "Pin this anchor? [y/N]: ")

	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read answer: %w", err)
	}

	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

// ConfirmNoMitmProtection asks the user to confirm before running an operation with every MITM protection disabled
// The prompt is shown only when TLS validation and anchor pinning are both off, which is the combination that leaves nothing verifying the server
func ConfirmNoMitmProtection(insecure bool, noTrustStore bool, yesIKnowWhatImDoing bool) error {
	// We need to show the warning only if both --insecure and --no-trust-store are set
	if !insecure || !noTrustStore {
		return nil
	}

	// Show the warning
	fmt.Fprintln(os.Stderr, "WARNING: --insecure and --no-trust-store disable all transport and anchor MITM protection")
	fmt.Fprintln(os.Stderr, "A network attacker can intercept TLS and substitute public keys for this operation")

	// The --yes-i-know-what-im-doing can be added for non-interactive use
	if yesIKnowWhatImDoing {
		fmt.Fprintln(os.Stderr, "Continuing because --yes-i-know-what-im-doing was provided")
		return nil
	}

	// If there's no interactive shell, return an error
	if !IsInteractiveTerminal() {
		return errors.New("refusing to combine --insecure with --no-trust-store without --yes-i-know-what-im-doing")
	}

	// Ask for confirmation
	fmt.Fprint(os.Stderr, "Type 'yes' to continue without MITM protection: ")
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}

	line = strings.ToLower(strings.TrimSpace(line))
	if line != "yes" {
		return errors.New("refusing to continue without MITM protection")
	}

	return nil
}
