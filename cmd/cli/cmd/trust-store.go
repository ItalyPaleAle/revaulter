package cmd

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

// trustStore persists pinned anchor public keys per (server, userId) tuple
// Pinning is TOFU: on first contact the CLI records both halves of the user's hybrid anchor; on every subsequent contact the CLI refuses to proceed if either half does not match the pinned value
// A mismatch is always surfaced as an explicit rotation prompt — the CLI never silently re-pins
type trustStore struct {
	Entries map[string]trustStoreEntry `json:"entries"`
	Path    string                     `json:"-"`
}

// trustStoreEntry is the per-target record. The fingerprint is redundant but
// stable — it's what humans compare when verifying a pin.
type trustStoreEntry struct {
	AnchorEs384PublicKey   string    `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string    `json:"anchorMldsa87PublicKey"`
	Fingerprint            string    `json:"fingerprint"`
	FirstSeen              time.Time `json:"firstSeen"`
}

// trustStoreKey returns the canonical map key for a (server, userId) pair
// Anchor identity belongs to the user, not to any particular request key that routes traffic to them, so pins survive request-key rotations
func trustStoreKey(server, userID string) string {
	return server + "|" + userID
}

// defaultTrustStorePath returns the default path for the trust store, creating the parent directory if needed
func defaultTrustStorePath() (string, error) {
	// If we have an env var "TRUST_STORE_PATH", use that
	env := os.Getenv("TRUST_STORE_PATH")
	if env != "" {
		return env, nil
	}

	// Get the user config dir as default
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate user config dir: %w", err)
	}

	return filepath.Join(base, "revaulter-cli", "trust.json"), nil
}

type trustStorePathFlags interface {
	GetTrustStorePath() string
}

// loadTrustStoreForFlags resolves the trust store path from CLI flags and loads it
func loadTrustStoreForFlags(flags trustStorePathFlags) (*trustStore, string, error) {
	path := flags.GetTrustStorePath()
	if path == "" {
		p, err := defaultTrustStorePath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}

	ts, err := loadTrustStore(path)
	if err != nil {
		return nil, "", err
	}

	return ts, path, nil
}

// loadTrustStore reads the trust store from disk
// A missing file returns an empty store; any other error (including invalid JSON) is returned
func loadTrustStore(path string) (*trustStore, error) {
	ts := &trustStore{
		Entries: make(map[string]trustStoreEntry),
		Path:    path,
	}

	// #nosec G304 -- path is controlled by the user via --trust-store or defaultTrustStorePath
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ts, nil
		}
		return nil, fmt.Errorf("failed to read trust store %q: %w", path, err)
	}

	err = json.Unmarshal(b, ts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust store %q: %w", path, err)
	}

	if ts.Entries == nil {
		ts.Entries = make(map[string]trustStoreEntry)
	}
	ts.Path = path

	return ts, nil
}

// saveTrustStore writes the trust store to disk with 0600 permissions
// The parent directory is created with 0700 if missing, and tightened to 0700 if it already existed with looser perms
func saveTrustStore(path string, ts *trustStore) error {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("failed to create trust store dir %q: %w", dir, err)
	}

	// os.MkdirAll only applies the permission bits to directories it newly creates
	// Explicitly chmod the leaf dir so an already-existing directory with looser perms gets tightened
	err = os.Chmod(dir, 0o700)
	if err != nil {
		return fmt.Errorf("failed to tighten trust store dir %q permissions: %w", dir, err)
	}

	b, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize trust store: %w", err)
	}

	// Write atomically via rename to avoid partial writes on crash.
	tmp, err := os.CreateTemp(dir, "trust-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	tmpPath := tmp.Name()
	defer func() {
		_ = os.RemoveAll(tmpPath)
	}()

	err = tmp.Chmod(0o600)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod trust store: %w", err)
	}

	_, err = tmp.Write(b)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write trust store: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return fmt.Errorf("failed to rename trust store: %w", err)
	}

	return nil
}

// verifyAndPinAnchor validates the hybrid anchor bundle in resp, verifies both signatures, then checks or pins the anchor in ts
// Returns pinned=true when the anchor was newly pinned; the caller must save the trust store in that case
func verifyAndPinAnchor(server string, resp *v2PubkeyResponse, ts *trustStore, confirm func(string) (bool, error)) (pinned bool, err error) {
	if len(resp.AnchorEs384PublicKey) == 0 || resp.AnchorMldsa87PublicKey == "" ||
		resp.PubkeyBundleSignatureEs384 == "" || resp.PubkeyBundleSignatureMldsa87 == "" {
		return false, errors.New("server did not return a hybrid anchor bundle; refusing to proceed (use --no-trust-store to override)")
	}

	if resp.UserID == "" {
		return false, errors.New("server did not return userId; refusing to proceed (use --no-trust-store to override)")
	}

	es384Pub, mldsa87PubBytes, err := parseAnchorPubkeysFromWire(resp.AnchorEs384PublicKey, resp.AnchorMldsa87PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid anchor public key: %w", err)
	}

	// Verify both halves of the hybrid bundle signature against the server-provided anchor pubkeys
	// The subsequent pin check catches anchor rotation; this catches a server that serves a corrupt or mismatched bundle
	es384JWK, err := protocolv2.ParseECP384PublicJWKCanonicalBody(resp.AnchorEs384PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid anchorEs384PublicKey: %w", err)
	}

	bundlePayload := &protocolv2.PubkeyBundlePayload{
		UserID:                 resp.UserID,
		RequestEncEcdhPubkey:   string(resp.EcdhP256),
		RequestEncMlkemPubkey:  resp.Mlkem768,
		AnchorEs384Crv:         es384JWK.Crv,
		AnchorEs384Kty:         es384JWK.Kty,
		AnchorEs384X:           es384JWK.X,
		AnchorEs384Y:           es384JWK.Y,
		AnchorMldsa87PublicKey: resp.AnchorMldsa87PublicKey,
		WrappedKeyEpoch:        resp.WrappedKeyEpoch,
	}
	sigEs, sigMl, err := decodeHybridSignatures(resp.PubkeyBundleSignatureEs384, resp.PubkeyBundleSignatureMldsa87)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey bundle signature: %w", err)
	}
	err = protocolv2.VerifyHybridBundle(es384Pub, mldsa87PubBytes, bundlePayload, sigEs, sigMl)
	if err != nil {
		return false, fmt.Errorf("pubkey bundle signature verification failed: %w", err)
	}

	return ts.checkOrPinAnchor(
		server, resp.UserID,
		es384Pub, resp.AnchorEs384PublicKey,
		resp.AnchorMldsa87PublicKey, mldsa87PubBytes,
		confirm,
	)
}

// checkOrPinAnchor matches the fetched anchor pubkey pair against the trust store
// - On first contact it prompts the user (TTY only) to accept the pin
// - On mismatch it refuses
// - On match it returns nil
//
// If confirm is nil, the function never prompts and fails closed on first contact; callers pass the terminal confirmer in interactive mode only.
func (ts *trustStore) checkOrPinAnchor(
	server, userID string,
	es384Pub *ecdsa.PublicKey,
	es384Canonical string,
	mldsa87PubB64 string,
	mldsa87PubBytes []byte,
	confirm func(fingerprint string) (bool, error),
) (pinned bool, err error) {
	fp, err := protocolv2.AnchorFingerprint(es384Pub, mldsa87PubBytes)
	if err != nil {
		return false, fmt.Errorf("compute anchor fingerprint: %w", err)
	}

	key := trustStoreKey(server, userID)
	entry, ok := ts.Entries[key]
	if ok {
		// Constant-time comparison on the fingerprint hex (same length on both sides)
		if subtle.ConstantTimeCompare([]byte(entry.Fingerprint), []byte(fp)) != 1 {
			return false, fmt.Errorf(
				"anchor fingerprint mismatch for %s (user %s); pinned=%s, server=%s; refusing to re-pin without explicit operator approval%s",
				server, userID, entry.Fingerprint, fp, ts.trustStorePathHint(),
			)
		}

		// Also check the pubkey components directly, so a bug in fingerprinting cannot mask a real mismatch
		if entry.AnchorMldsa87PublicKey != mldsa87PubB64 {
			return false, fmt.Errorf("anchor ML-DSA-87 pubkey does not match pin for %s (user %s)%s", server, userID, ts.trustStorePathHint())
		}

		if subtle.ConstantTimeCompare([]byte(entry.AnchorEs384PublicKey), []byte(es384Canonical)) != 1 {
			return false, fmt.Errorf("anchor ES384 pubkey does not match pin for %s (user %s)%s", server, userID, ts.trustStorePathHint())
		}

		return false, nil
	}

	// First contact
	if confirm == nil {
		return false, fmt.Errorf(
			"anchor for %s (user %s) is not pinned yet (fingerprint %s); rerun with a TTY or --no-trust-store",
			server, userID, fp,
		)
	}
	accepted, err := confirm(fp)
	if err != nil {
		return false, err
	}
	if !accepted {
		return false, errors.New("anchor pin declined by user")
	}
	ts.Entries[key] = trustStoreEntry{
		AnchorEs384PublicKey:   es384Canonical,
		AnchorMldsa87PublicKey: mldsa87PubB64,
		Fingerprint:            fp,
		FirstSeen:              time.Now().UTC(),
	}
	return true, nil
}

// trustStorePathHint returns an operator hint for anchor rotation errors
func (ts *trustStore) trustStorePathHint() string {
	if ts.Path == "" {
		return ""
	}

	return "; trust store: " + ts.Path
}
