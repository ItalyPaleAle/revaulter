package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/http2"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/integrity"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

type checkFlags struct {
	Server          string
	Insecure        bool
	NoH2C           bool
	NoRekorFallback bool
	Timeout         durationValue
}

type checkInfoResponse struct {
	Product      string `json:"product"`
	APIVersion   int    `json:"apiVersion"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	BuildDate    string `json:"buildDate"`
	HasIntegrity bool   `json:"hasIntegrity"`
}

type checkIntegrityResponse struct {
	Manifest string          `json:"manifest"`
	Bundle   json.RawMessage `json:"bundle"`
}

func init() {
	rootCmd.AddCommand(newCheckCmd())
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
(%s/.github/workflows/release.yaml) on a tag or main-branch build,
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

	f.Server = strings.TrimSuffix(f.Server, "/")
	if f.Server == "" {
		return errors.New("--server is required")
	}

	timeout := time.Duration(f.Timeout)
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	client, err := newCheckHTTPClient(f)
	if err != nil {
		return err
	}

	// Step 1: fetch /info
	info, err := fetchInfo(ctx, client, f.Server)
	if err != nil {
		return fmt.Errorf("fetch /info: %w", err)
	}
	if !info.HasIntegrity {
		return errors.New("server reports hasIntegrity=false: this build does not carry a signed integrity manifest (non-production build); integrity cannot be verified")
	}
	log.Info("Server info",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("buildDate", info.BuildDate),
	)

	// Step 2: fetch /info/integrity
	artifacts, err := fetchIntegrity(ctx, client, f.Server)
	if err != nil {
		return fmt.Errorf("fetch /info/integrity: %w", err)
	}

	manifestBytes := []byte(artifacts.Manifest)

	// Step 3: verify the cosign keyless signature
	// Primary path: verify the inline bundle offline against embedded trust roots
	// Fallback (unless --no-rekor-fallback): if the inline bundle fails, query Rekor by manifest hash
	// and reconstruct a bundle from the log entry
	result, primaryErr := integrity.VerifyBundle(manifestBytes, artifacts.Bundle)
	switch {
	case primaryErr == nil:
		// Primary succeeded
	case f.NoRekorFallback:
		return fmt.Errorf("signature verification failed: %w", primaryErr)
	default:
		log.Warn("Inline bundle verification failed, falling back to live Rekor query",
			slog.String("error", primaryErr.Error()),
		)
		fbResult, fbErr := integrity.VerifyViaRekor(ctx, manifestBytes, "")
		if fbErr != nil {
			return fmt.Errorf("signature verification failed: primary=%v; rekor fallback=%w", primaryErr, fbErr)
		}
		result = fbResult
	}
	if result != nil && result.Signature != nil && result.Signature.Certificate != nil {
		log.Info("Signature verified",
			slog.String("subject", result.Signature.Certificate.SubjectAlternativeName),
			slog.String("issuer", result.Signature.Certificate.Issuer),
		)
	}

	// Step 4: parse the manifest and assert downgrade protection
	manifest, err := integrity.Parse(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.Version != info.Version {
		return fmt.Errorf("manifest version %q does not match /info version %q (possible downgrade)", manifest.Version, info.Version)
	}
	if manifest.Commit != info.Commit {
		return fmt.Errorf("manifest commit %q does not match /info commit %q (possible downgrade)", manifest.Commit, info.Commit)
	}

	// Step 5: fetch each file and hash it
	mismatches, err := verifyManifestFiles(ctx, client, f.Server, manifest)
	if err != nil {
		return err
	}
	if len(mismatches) > 0 {
		fmt.Fprintf(os.Stderr, "Integrity check FAILED: %d file(s) did not match\n", len(mismatches))
		for _, m := range mismatches {
			fmt.Fprintf(os.Stderr, "  - %s\n", m)
		}
		return fmt.Errorf("%d file(s) failed integrity check", len(mismatches))
	}

	fmt.Fprintf(os.Stdout,
		"Integrity verified: version %s (commit %s), %d files\n",
		manifest.Version, manifest.Commit, len(manifest.Files),
	)
	return nil
}

func fetchInfo(ctx context.Context, client *http.Client, server string) (*checkInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/info", nil)
	if err != nil {
		return nil, err
	}

	var res checkInfoResponse
	err = doJSONRequest(client, req, &res)
	if err != nil {
		return nil, err
	}

	if res.APIVersion != 2 {
		return nil, fmt.Errorf("unexpected apiVersion %d (expected 2)", res.APIVersion)
	}

	return &res, nil
}

func fetchIntegrity(ctx context.Context, client *http.Client, server string) (*checkIntegrityResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/info/integrity", nil)
	if err != nil {
		return nil, err
	}

	var res checkIntegrityResponse
	err = doJSONRequest(client, req, &res)
	if err != nil {
		return nil, err
	}
	if res.Manifest == "" {
		return nil, errors.New("server returned an empty manifest")
	}

	// An empty bundle is tolerated here — the Rekor fallback can still verify
	// by looking up the manifest digest directly in the transparency log
	return &res, nil
}

// verifyManifestFiles downloads each file listed in the manifest, hashes it, and compares against the manifest entry.
// It returns a list of human-readable mismatch descriptions (empty on success).
func verifyManifestFiles(ctx context.Context, client *http.Client, server string, manifest integrity.Manifest) ([]string, error) {
	log := logging.LogFromContext(ctx)

	var mismatches []string
	for _, f := range manifest.Files {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}

		gotSha, gotSize, err := hashRemoteFile(ctx, client, server+"/"+f.Path)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", f.Path, err)
		}

		switch {
		case gotSize != f.Size:
			mismatches = append(mismatches, fmt.Sprintf("%s: size mismatch (manifest=%d, actual=%d)", f.Path, f.Size, gotSize))
		case gotSha != f.Sha256:
			mismatches = append(mismatches, fmt.Sprintf("%s: sha256 mismatch (manifest=%s, actual=%s)", f.Path, f.Sha256, gotSha))
		default:
			log.Debug("ok", slog.String("path", f.Path))
		}
	}

	return mismatches, nil
}

func hashRemoteFile(ctx context.Context, client *http.Client, fullURL string) (sha string, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return "", 0, err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("unexpected status %d", res.StatusCode)
	}

	h := sha256.New()
	n, err := io.Copy(h, res.Body)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func newCheckHTTPClient(f *checkFlags) (*http.Client, error) {
	serverURL, err := url.Parse(f.Server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	transport := &http2.Transport{
		IdleConnTimeout:  90 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}

	if serverURL.Scheme == "http" && !f.NoH2C {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	if f.Insecure {
		transport.TLSClientConfig = &tls.Config{
			// #nosec G402
			InsecureSkipVerify: true,
		}
	}

	return &http.Client{Transport: transport}, nil
}
