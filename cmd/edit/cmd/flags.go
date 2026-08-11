package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/cliutil"
	"github.com/italypaleale/revaulter/pkg/revaulter"
)

// Environment variables that provide defaults for the flags that would otherwise have to be repeated on every invocation
const (
	envServer     = "REVAULTER_SERVER"
	envRequestKey = "REVAULTER_REQUEST_KEY"
	envKeyLabel   = "REVAULTER_KEY_LABEL"
)

// userAgent is the User-Agent header value sent on all HTTP requests
var userAgent = "RevaulterEdit/" + buildinfo.AppVersion

// commonFlags are the flags shared by every sub-command
type commonFlags struct {
	Server     string
	RequestKey string
	KeyLabel   string
	Algorithm  string

	Timeout time.Duration
	Note    string

	Insecure bool
	NoH2C    bool

	TrustStorePath      string
	NoTrustStore        bool
	YesIKnowWhatImDoing bool

	Verbose bool
}

func (f *commonFlags) Bind(cmd *cobra.Command) {
	defaultPath, _ := revaulter.DefaultTrustStorePath()

	var trustStoreDefault string
	if defaultPath != "" {
		trustStoreDefault = " (defaults to " + defaultPath + ")"
	}

	flags := cmd.PersistentFlags()
	flags.StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server (defaults to "+envServer+")")
	flags.StringVarP(&f.RequestKey, "request-key", "k", "", "Per-user request key used to authenticate with the server (defaults to "+envRequestKey+")")
	flags.StringVarP(&f.KeyLabel, "key-label", "l", "", "Logical key label used to wrap the file's encryption key (defaults to "+envKeyLabel+"); files that already exist carry their own label")
	flags.StringVarP(&f.Algorithm, "algorithm", "a", revaulter.AlgorithmA256GCM, "Algorithm used to wrap the file's encryption key: 'A256GCM' or 'C20P'")

	flags.DurationVarP(&f.Timeout, "timeout", "t", 0, "Timeout for the approval request, as a Go duration (e.g. '5m')")
	flags.StringVarP(&f.Note, "note", "n", "", "Message displayed alongside the request; defaults to the name of the file")

	flags.BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	flags.BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")

	flags.StringVar(&f.TrustStorePath, "trust-store", "", "Path to the anchor trust store"+trustStoreDefault)
	flags.BoolVar(&f.NoTrustStore, "no-trust-store", false, "Skip anchor pinning and hybrid bundle verification (equivalent to SSH StrictHostKeyChecking=no)")

	flags.BoolVar(&f.YesIKnowWhatImDoing, "yes-i-know-what-im-doing", false, "Allow combining --insecure with --no-trust-store without an interactive confirmation")
	_ = flags.MarkHidden("yes-i-know-what-im-doing")

	flags.BoolVarP(&f.Verbose, "verbose", "V", false, "Show debug-level logs")
}

// Validate applies the environment variable defaults and checks that the flags are usable
func (f *commonFlags) Validate() error {
	if f.Server == "" {
		f.Server = os.Getenv(envServer)
	}
	if f.RequestKey == "" {
		f.RequestKey = os.Getenv(envRequestKey)
	}

	if f.KeyLabel == "" {
		f.KeyLabel = os.Getenv(envKeyLabel)
	}

	f.Server = strings.TrimSuffix(f.Server, "/")
	if f.Server == "" {
		return errors.New("--server is required (or set " + envServer + ")")
	}
	if f.RequestKey == "" {
		return errors.New("--request-key is required (or set " + envRequestKey + ")")
	}

	return cliutil.ConfirmNoMitmProtection(f.Insecure, f.NoTrustStore, f.YesIKnowWhatImDoing)
}

// newClient returns a Revaulter client configured from the flags
func (f *commonFlags) newClient(log *slog.Logger) (*revaulter.Client, error) {
	return revaulter.New(revaulter.Options{
		Server:         f.Server,
		RequestKey:     f.RequestKey,
		Insecure:       f.Insecure,
		NoH2C:          f.NoH2C,
		UserAgent:      userAgent,
		Logger:         log,
		TrustStorePath: f.TrustStorePath,
		NoTrustStore:   f.NoTrustStore,
		ConfirmAnchor:  terminalAnchorConfirmer(),
		Timeout:        f.Timeout,
	})
}

// terminalAnchorConfirmer returns a prompt function that asks the user to accept a server's anchor on first contact
// If the terminal is not interactive it returns nil, so the client fails closed rather than pinning silently
func terminalAnchorConfirmer() revaulter.AnchorConfirmFunc {
	if !cliutil.IsInteractiveTerminal() {
		return nil
	}

	return func(anchor revaulter.AnchorInfo) (bool, error) {
		return cliutil.AnchorPrompt(anchor.Server, anchor.Fingerprint)
	}
}

// fileArg returns the path of the file to operate on, which every sub-command takes as its only argument
func fileArg(args []string) (string, error) {
	switch len(args) {
	case 1:
		if args[0] == "" {
			return "", errors.New("the path of the file cannot be empty")
		}
		return args[0], nil
	case 0:
		return "", errors.New("the path of a file is required")
	default:
		return "", fmt.Errorf("expected a single file path, got %d arguments", len(args))
	}
}
