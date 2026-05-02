package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/integrity/verifier"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

type checkFlags struct {
	Server          string
	Insecure        bool
	NoH2C           bool
	NoRekorFallback bool
	Timeout         durationValue
}

func newCheckCmd() *cobra.Command {
	f := &checkFlags{}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Verify that a Revaulter server is serving unmodified web client assets",
		Long: fmt.Sprintf(`check fetches the signed integrity manifest from the server at GET /info/integrity,
verifies its cosign keyless signature against Sigstore's public infrastructure roots embedded in this CLI,
then downloads every listed asset and compares its SHA-256 against the signed manifest.

A release is considered genuine only if the signature identity matches this CLI's release workflow
(%s/.github/workflows/release.yaml) on a tag or another ref baked into this CLI build,
and its entry is present in the Rekor transparency log.`, buildinfo.RepoURL),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd.Context(), f)
		},
	}
	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")
	cmd.Flags().BoolVar(&f.NoRekorFallback, "no-rekor-fallback", false, "Disable the live Rekor fallback; require the inline bundle to verify standalone")
	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Overall timeout for the check (e.g. 60s, 2m)")
	return cmd
}

func runCheck(parent context.Context, f *checkFlags) error {
	log := logging.LogFromContext(parent)

	if f.Server == "" {
		return errors.New("--server is required")
	}

	timeout := time.Duration(f.Timeout)
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	client, err := verifier.NewHTTPClient(f.Server, f.Insecure, f.NoH2C)
	if err != nil {
		return err
	}

	result, err := verifier.Check(ctx, verifier.Options{
		Server:          f.Server,
		HTTPClient:      client,
		NoRekorFallback: f.NoRekorFallback,
		Logger:          log,
	})
	if err != nil {
		return err
	}

	if len(result.Mismatches) > 0 {
		fmt.Fprintf(os.Stderr, "Integrity check FAILED: %d file(s) did not match\n", len(result.Mismatches))
		for _, m := range result.Mismatches {
			fmt.Fprintf(os.Stderr, "  - %s\n", m.String())
		}
		return fmt.Errorf("%d file(s) failed integrity check", len(result.Mismatches))
	}

	fmt.Fprintf(os.Stdout,
		"Integrity verified: version %s (commit %s), %d files\n",
		result.Manifest.Version, result.Manifest.Commit, result.FileCount,
	)
	return nil
}
