package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/italypaleale/revaulter/internal/buildinfo"
	"github.com/italypaleale/revaulter/internal/integrity/verifier"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

type checkFlags struct {
	Server          string
	Insecure        bool
	NoH2C           bool
	NoRekorFallback bool
	MinVersion      string
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
and its entry is present in the Rekor transparency log.

A compromised server can still pass by serving an older release that was genuinely signed.
check warns when the server runs an older release than this CLI, and --min-version turns that into a failure for any release older than the given version.`, buildinfo.RepoURL),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd.Context(), f)
		},
	}
	cmd.Flags().StringVarP(&f.Server, "server", "s", "", "Address of the Revaulter server")
	_ = cmd.MarkFlagRequired("server")
	cmd.Flags().BoolVar(&f.Insecure, "insecure", false, "Skip TLS certificate validation when connecting to the Revaulter server")
	cmd.Flags().BoolVar(&f.NoH2C, "no-h2c", false, "Do not attempt connecting with HTTP/2 Cleartext when not using TLS")
	cmd.Flags().BoolVar(&f.NoRekorFallback, "no-rekor-fallback", false, "Disable the live Rekor fallback; require the inline bundle to verify standalone")
	cmd.Flags().StringVar(&f.MinVersion, "min-version", "", "Fail if the server runs a release older than this version (e.g. x.y.z)")
	cmd.Flags().VarP(&f.Timeout, "timeout", "t", "Overall timeout for the check (e.g. 60s, 2m)")
	return cmd
}

func runCheck(parent context.Context, f *checkFlags) error {
	log := logging.LogFromContext(parent)

	if f.Server == "" {
		return errors.New("--server is required")
	}
	if f.MinVersion != "" && releaseSemver(f.MinVersion) == "" {
		return fmt.Errorf("--min-version %q is not a valid release version", f.MinVersion)
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

	// The manifest version is signed and was checked against /info, so it's the version the server runs
	warning, err := checkServerVersion(result.Manifest.Version, buildinfo.AppVersion, f.MinVersion)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout,
		"Integrity verified: version %s (commit %s), %d files\n",
		result.Manifest.Version, result.Manifest.Commit, result.FileCount,
	)
	if warning != "" {
		fmt.Fprintln(os.Stderr, "Warning: "+warning)
	}
	return nil
}

// checkServerVersion compares the version of a verified release with this CLI's version and with the optional minimum version
// A signature check alone can't detect a server serving an older release that was genuinely signed, so this is the only protection against downgrades
// It returns an error when the server is older than minVersion, and a warning when it's older than this CLI
// Versions that aren't releases, such as "edge" for builds from the main branch, can't be compared: they never produce a warning, and they fail the minimum version check
func checkServerVersion(serverVersion string, cliVersion string, minVersion string) (warning string, err error) {
	server := releaseSemver(serverVersion)

	if minVersion != "" {
		minimum := releaseSemver(minVersion)
		if minimum == "" {
			return "", fmt.Errorf("--min-version %q is not a valid release version", minVersion)
		}

		if server == "" {
			return "", fmt.Errorf("the server's web client is genuine, but it runs %q, which isn't a release version and can't be compared with --min-version %s", serverVersion, minVersion)
		}

		if semver.Compare(server, minimum) < 0 {
			return "", fmt.Errorf("the server's web client is genuine, but it runs version %s, which is older than --min-version %s", serverVersion, minVersion)
		}
	}

	cli := releaseSemver(cliVersion)
	if server != "" && cli != "" && semver.Compare(server, cli) < 0 {
		return fmt.Sprintf("the server runs version %s, which is older than this CLI (%s). A compromised server can pass this check by serving an older release, so make sure the server is meant to run this version", serverVersion, cliVersion), nil
	}

	return "", nil
}

// releaseSemver returns a release version in the "vMAJOR.MINOR.PATCH" form that golang.org/x/mod/semver expects, or an empty string if it isn't a release version
// Release builds report their version without the leading "v", for example "2.9.0"
func releaseSemver(version string) string {
	if version == "" {
		return ""
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !semver.IsValid(version) {
		return ""
	}

	return version
}
