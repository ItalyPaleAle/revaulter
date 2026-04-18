package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/italypaleale/revaulter/pkg/integrity"
)

// Options controls a single run of Check
type Options struct {
	// Server is the Revaulter base URL (trailing slash optional; trimmed by Check)
	Server string

	// HTTPClient is the client used for all requests to Server
	// Callers typically build one via NewHTTPClient; nil defaults to http.DefaultClient
	HTTPClient *http.Client

	// NoRekorFallback disables the live Rekor lookup; the inline bundle must verify standalone
	NoRekorFallback bool

	// RepoURL overrides the identity-policy repo URL
	// Leave empty to fall back to buildinfo.RepoURL (the default for CLI callers built with ldflags)
	RepoURL string

	// Logger is optional; nil silences per-file debug output
	Logger *slog.Logger
}

// InfoResponse mirrors the JSON returned by GET /info
type InfoResponse struct {
	Product      string `json:"product"`
	APIVersion   int    `json:"apiVersion"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	BuildDate    string `json:"buildDate"`
	HasIntegrity bool   `json:"hasIntegrity"`
}

// SignatureIdentity is the verified signer's identity, as extracted from the cosign cert
type SignatureIdentity struct {
	Subject string
	Issuer  string
}

// Mismatch describes a file whose served content diverges from the signed manifest
type Mismatch struct {
	Path     string
	Reason   string // "size" or "sha256"
	Expected string
	Actual   string
}

// String returns a human-readable mismatch description matching the old CLI output
func (m Mismatch) String() string {
	switch m.Reason {
	case "size":
		return fmt.Sprintf("%s: size mismatch (manifest=%s, actual=%s)", m.Path, m.Expected, m.Actual)
	case "sha256":
		return fmt.Sprintf("%s: sha256 mismatch (manifest=%s, actual=%s)", m.Path, m.Expected, m.Actual)
	default:
		return fmt.Sprintf("%s: %s mismatch (manifest=%s, actual=%s)", m.Path, m.Reason, m.Expected, m.Actual)
	}
}

// Result is the structured outcome of a successful end-to-end verification
// A non-empty Mismatches slice indicates the signature and manifest verified, but the server is
// currently serving altered files — callers decide whether to treat that as an error
type Result struct {
	Info       InfoResponse
	Manifest   integrity.Manifest
	Identity   SignatureIdentity
	UsedRekor  bool
	FileCount  int
	Mismatches []Mismatch
}

// integrityResponse mirrors the JSON returned by GET /info/integrity
type integrityResponse struct {
	Manifest string          `json:"manifest"`
	Bundle   json.RawMessage `json:"bundle"`
}

// Check runs the full end-to-end verification flow against opts.Server
// It returns an error only for operational/cryptographic failures; a signed manifest whose files
// merely diverge from what the server is currently serving is reported via Result.Mismatches
// with a nil error
func Check(ctx context.Context, opts Options) (*Result, error) {
	server := strings.TrimSuffix(opts.Server, "/")
	if server == "" {
		return nil, errors.New("server is required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	// Step 1: fetch /info
	info, err := fetchInfo(ctx, client, server)
	if err != nil {
		return nil, fmt.Errorf("fetch /info: %w", err)
	}
	if !info.HasIntegrity {
		return nil, ErrNoIntegrity
	}
	log.Info("Server info",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("buildDate", info.BuildDate),
	)

	// Step 2: fetch /info/integrity
	artifacts, err := fetchIntegrity(ctx, client, server)
	if err != nil {
		return nil, fmt.Errorf("fetch /info/integrity: %w", err)
	}
	manifestBytes := []byte(artifacts.Manifest)

	// Step 3: verify the cosign keyless signature
	// Primary path: verify the inline bundle offline against embedded trust roots
	// Fallback (unless NoRekorFallback): if the inline bundle fails, query Rekor by manifest hash
	// and reconstruct a bundle from the log entry
	policy := integrity.Policy{RepoURL: opts.RepoURL}
	usedRekor := false
	vr, primaryErr := integrity.VerifyBundleWithPolicy(manifestBytes, artifacts.Bundle, policy)
	switch {
	case primaryErr == nil:
		// Primary succeeded
	case opts.NoRekorFallback:
		return nil, fmt.Errorf("signature verification failed: %w", primaryErr)
	default:
		log.Warn("Inline bundle verification failed, falling back to live Rekor query",
			slog.String("error", primaryErr.Error()),
		)
		fbResult, fbErr := integrity.VerifyViaRekorWithPolicy(ctx, manifestBytes, "", policy)
		if fbErr != nil {
			return nil, fmt.Errorf("signature verification failed: primary=%s; rekor fallback=%w", primaryErr.Error(), fbErr)
		}
		vr = fbResult
		usedRekor = true
	}

	var identity SignatureIdentity
	if vr != nil && vr.Signature != nil && vr.Signature.Certificate != nil {
		identity = SignatureIdentity{
			Subject: vr.Signature.Certificate.SubjectAlternativeName,
			Issuer:  vr.Signature.Certificate.Issuer,
		}
		log.Info("Signature verified",
			slog.String("subject", identity.Subject),
			slog.String("issuer", identity.Issuer),
		)
	}

	// Step 4: parse the manifest and assert downgrade protection
	manifest, err := integrity.Parse(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.Version != info.Version {
		return nil, fmt.Errorf("manifest version %q does not match /info version %q (possible downgrade)", manifest.Version, info.Version)
	}
	if manifest.Commit != info.Commit {
		return nil, fmt.Errorf("manifest commit %q does not match /info commit %q (possible downgrade)", manifest.Commit, info.Commit)
	}

	// Step 5: fetch each file and hash it; accumulate mismatches
	mismatches, err := verifyManifestFiles(ctx, client, log, server, manifest)
	if err != nil {
		return nil, err
	}

	return &Result{
		Info: InfoResponse{
			Product:      info.Product,
			APIVersion:   info.APIVersion,
			Version:      info.Version,
			Commit:       info.Commit,
			BuildDate:    info.BuildDate,
			HasIntegrity: info.HasIntegrity,
		},
		Manifest:   manifest,
		Identity:   identity,
		UsedRekor:  usedRekor,
		FileCount:  len(manifest.Files),
		Mismatches: mismatches,
	}, nil
}

func fetchInfo(ctx context.Context, client *http.Client, server string) (*InfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/info", nil)
	if err != nil {
		return nil, err
	}

	var res InfoResponse
	err = doJSONRequest(client, req, &res)
	if err != nil {
		return nil, err
	}

	if res.APIVersion != 2 {
		return nil, fmt.Errorf("%w %d (expected 2)", ErrUnexpectedAPIVer, res.APIVersion)
	}

	return &res, nil
}

func fetchIntegrity(ctx context.Context, client *http.Client, server string) (*integrityResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/info/integrity", nil)
	if err != nil {
		return nil, err
	}

	var res integrityResponse
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

// verifyManifestFiles downloads each file listed in the manifest, hashes it, and compares against the manifest entry
// It returns the mismatch list (empty on success) plus any operational error
func verifyManifestFiles(ctx context.Context, client *http.Client, log *slog.Logger, server string, manifest integrity.Manifest) ([]Mismatch, error) {
	var mismatches []Mismatch
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
			mismatches = append(mismatches, Mismatch{
				Path:     f.Path,
				Reason:   "size",
				Expected: strconv.FormatInt(f.Size, 10),
				Actual:   strconv.FormatInt(gotSize, 10),
			})
		case gotSha != f.Sha256:
			mismatches = append(mismatches, Mismatch{
				Path:     f.Path,
				Reason:   "sha256",
				Expected: f.Sha256,
				Actual:   gotSha,
			})
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
