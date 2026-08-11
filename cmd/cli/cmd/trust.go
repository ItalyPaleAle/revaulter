package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/cliutil"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

type trustCmd struct {
	Server         string
	RequestKey     string
	Insecure       bool
	NoH2C          bool
	TrustStorePath string
	Yes            bool
}

// These methods implement coreClientFlags so trustCmd can be passed to newCoreClient
func (c *trustCmd) GetServer() string {
	return c.Server
}

func (c *trustCmd) GetRequestKey() string {
	return c.RequestKey
}

func (c *trustCmd) GetConnectionOptions() (bool, bool) {
	return c.Insecure, c.NoH2C
}

func (c *trustCmd) GetTrustStorePath() string {
	return c.TrustStorePath
}

func (c *trustCmd) GetNoTrustStore() bool {
	return false
}

func newTrustCmd() *cobra.Command {
	impl := &trustCmd{}
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Pin a Revaulter server's anchor in the local trust store",
		Long: `Connects to a Revaulter server, fetches its hybrid anchor public keys (ES384 + ML-DSA-87), verifies the bundle signatures, and pins the anchor fingerprint in the local trust store using TOFU (Trust On First Use).

Run this once when first connecting to a server.
All subsequent commands (sign, encrypt, decrypt, ssh-agent) verify the pinned anchor and refuse to proceed if it changes unexpectedly.

If the anchor is already pinned and matches, the command confirms it and exits successfully.`,
		RunE: impl.Run,
	}

	defaultPath, _ := clientcore.DefaultTrustStorePath()
	var trustStoreDefault string
	if defaultPath != "" {
		trustStoreDefault = " (defaults to " + defaultPath + ")"
	}

	// Set flags
	cmd.Flags().StringVarP(&impl.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().StringVarP(&impl.RequestKey, "request-key", "k", "", "Per-user request key used to authenticate with the server")
	_ = cmd.MarkFlagRequired("request-key")
	cmd.Flags().BoolVar(&impl.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&impl.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")
	cmd.Flags().StringVar(&impl.TrustStorePath, "trust-store", "", "Path to the anchor trust store"+trustStoreDefault)
	cmd.Flags().BoolVarP(&impl.Yes, "yes", "y", false, "Accept the anchor fingerprint without prompting (for non-interactive use)")

	return cmd
}

func (c *trustCmd) Run(cmd *cobra.Command, _ []string) error {
	log := logging.LogFromContext(cmd.Context())
	c.Server = strings.TrimSuffix(c.Server, "/")

	// Get a client for the server
	client, err := newCoreClient(log, c, nil)
	if err != nil {
		return err
	}

	// Resolve the trust store path and load the trust store
	path, err := client.TrustStorePath()
	if err != nil {
		return err
	}

	ts, err := clientcore.LoadTrustStore(path)
	if err != nil {
		return err
	}

	// Fetch the pubkey bundle
	resp, err := client.FetchPubkeyBundle(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to fetch server pubkey bundle: %w", err)
	}

	pinned, err := clientcore.VerifyAndPinAnchor(c.Server, resp, ts, c.anchorConfirmer())
	if err != nil {
		return err
	}

	// Pin if the user confirmed
	if pinned {
		err = clientcore.SaveTrustStore(path, ts)
		if err != nil {
			return fmt.Errorf("save trust store: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Anchor pinned for %s (user %s)\nTrust store: %s\n", c.Server, resp.UserID, path)
		log.Info("Anchor pinned",
			slog.String("server", c.Server),
			slog.String("user_id", resp.UserID),
			slog.String("trust_store", path),
		)
	} else {
		fmt.Fprintf(os.Stderr, "Anchor for %s (user %s) is already pinned — verified OK\n", c.Server, resp.UserID)
	}

	return nil
}

// anchorConfirmer builds the confirmer used for first-contact pinning
// --yes accepts without prompting (for scripts/CI), otherwise a TTY is required
func (c *trustCmd) anchorConfirmer() clientcore.ConfirmAnchorFunc {
	if c.Yes {
		return func(server, userID, fingerprint string) (bool, error) {
			fmt.Fprintf(os.Stderr, "Pinning anchor for %s (user %s) without confirmation (--yes).\n", server, userID)
			fmt.Fprintf(os.Stderr, "Anchor fingerprint:\n%s\n", clientcore.FormatFingerprint(fingerprint, 2))
			return true, nil
		}
	}

	if !cliutil.IsInteractiveTerminal() {
		return func(server, userID, fingerprint string) (bool, error) {
			return false, fmt.Errorf(
				"anchor for %s (user %s) is not pinned yet (fingerprint %s); rerun with a TTY or use --yes for non-interactive pinning",
				server, userID, fingerprint,
			)
		}
	}

	// Prompt the user for confirmation
	reader := bufio.NewReader(os.Stdin)
	return func(server, userID, fingerprint string) (bool, error) {
		fmt.Fprintf(os.Stderr, "First contact with %s (user %s).\n", server, userID)
		fmt.Fprintf(os.Stderr, "Anchor fingerprint:\n%s\n", clientcore.FormatFingerprint(fingerprint, 2))
		fmt.Fprint(os.Stderr, "Pin this anchor? [y/N]: ")

		// Read the response
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("read answer: %w", err)
		}

		line = strings.ToLower(strings.TrimSpace(line))
		return line == "y" || line == "yes", nil
	}
}
