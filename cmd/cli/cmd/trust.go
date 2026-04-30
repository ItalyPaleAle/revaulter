package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

type trustCmd struct {
	Server         string
	RequestKey     string
	Insecure       bool
	NoH2C          bool
	TrustStorePath string
}

// GetServer and GetConnectionOptions implement httpClientFlags so trustCmd can be passed to getV2HTTPClient
func (c *trustCmd) GetServer() string                  { return c.Server }
func (c *trustCmd) GetConnectionOptions() (bool, bool) { return c.Insecure, c.NoH2C }

func newTrustCmd() *cobra.Command {
	impl := &trustCmd{}
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Pin a Revaulter server's anchor in the local trust store",
		Long: `Connects to a Revaulter server, fetches its hybrid anchor public keys
(ES384 + ML-DSA-87), verifies the bundle signatures, and pins the anchor
fingerprint in the local trust store using TOFU (Trust On First Use).

Run this once when first connecting to a server. All subsequent commands
(sign, encrypt, decrypt, ssh-agent) verify the pinned anchor and refuse
to proceed if it changes unexpectedly.

If the anchor is already pinned and matches, the command confirms it and exits successfully.`,
		RunE: impl.Run,
	}

	defaultPath, _ := defaultTrustStorePath()
	var trustStoreDefault string
	if defaultPath != "" {
		trustStoreDefault = " (defaults to " + defaultPath + ")"
	}

	cmd.Flags().StringVarP(&impl.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().StringVarP(&impl.RequestKey, "request-key", "k", "", "Per-user request key used to authenticate with the server")
	_ = cmd.MarkFlagRequired("request-key")
	cmd.Flags().BoolVar(&impl.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&impl.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")
	cmd.Flags().StringVar(&impl.TrustStorePath, "trust-store", "", "Path to the anchor trust store"+trustStoreDefault)

	return cmd
}

func (c *trustCmd) Run(cmd *cobra.Command, _ []string) error {
	log := logging.LogFromContext(cmd.Context())
	c.Server = strings.TrimSuffix(c.Server, "/")

	httpClient, err := getV2HTTPClient(log, c)
	if err != nil {
		return err
	}

	// Resolve trust store path
	path := c.TrustStorePath
	if path == "" {
		path, err = defaultTrustStorePath()
		if err != nil {
			return err
		}
	}

	ts, err := loadTrustStore(path)
	if err != nil {
		return err
	}

	// Fetch the pubkey bundle
	req, err := newV2RequestKeyHTTPRequest(cmd.Context(), http.MethodGet, c.Server, c.RequestKey, "pubkey", nil)
	if err != nil {
		return err
	}

	var resp v2PubkeyResponse
	if err = doJSONRequest(httpClient, req, &resp); err != nil {
		return fmt.Errorf("failed to fetch server pubkey bundle: %w", err)
	}

	// Build an interactive confirmer. The trust command is designed for first-contact
	// setup; if the anchor isn't pinned yet and we're not on a TTY, fail closed so the
	// user knows they need to run this interactively.
	stdinFd := int(os.Stdin.Fd())   // #nosec G115
	stderrFd := int(os.Stderr.Fd()) // #nosec G115
	var confirm func(string) (bool, error)
	if term.IsTerminal(stdinFd) && term.IsTerminal(stderrFd) {
		reader := bufio.NewReader(os.Stdin)
		server, userID := c.Server, resp.UserID
		confirm = func(fp string) (bool, error) {
			fmt.Fprintf(os.Stderr, "First contact with %s (user %s).\n", server, userID)
			fmt.Fprintf(os.Stderr, "Anchor fingerprint (SHA-256 of ES384||ML-DSA-87 pubkeys):\n  %s\n", fp)
			fmt.Fprint(os.Stderr, "Pin this anchor? [y/N]: ")
			line, err := reader.ReadString('\n')
			if err != nil {
				return false, fmt.Errorf("read answer: %w", err)
			}
			line = strings.ToLower(strings.TrimSpace(line))
			return line == "y" || line == "yes", nil
		}
	}

	pinned, err := verifyAndPinAnchor(c.Server, &resp, ts, confirm)
	if err != nil {
		return err
	}

	if pinned {
		if err = saveTrustStore(path, ts); err != nil {
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
