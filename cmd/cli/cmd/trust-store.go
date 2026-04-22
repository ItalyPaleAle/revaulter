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
}

// trustStoreEntry is the per-target record. The fingerprint is redundant but
// stable — it's what humans compare when verifying a pin.
type trustStoreEntry struct {
	AnchorEs384PublicKey   json.RawMessage `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string          `json:"anchorMldsa87PublicKey"`
	Fingerprint            string          `json:"fingerprint"`
	FirstSeen              time.Time       `json:"firstSeen"`
}

// trustStoreKey returns the canonical map key for a (server, userId) pair
// Anchor identity belongs to the user, not to any particular request key that routes traffic to them, so pins survive request-key rotations
func trustStoreKey(server, userID string) string {
	return server + "|" + userID
}

// defaultTrustStorePath returns the default path for the trust store, creating
// the parent directory if needed.
func defaultTrustStorePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate user config dir: %w", err)
	}
	return filepath.Join(base, "revaulter-cli", "trust.json"), nil
}

// loadTrustStore reads the trust store from disk. A missing file returns an
// empty store; any other error (including invalid JSON) is returned.
func loadTrustStore(path string) (*trustStore, error) {
	ts := &trustStore{Entries: make(map[string]trustStoreEntry)}
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
	return ts, nil
}

// saveTrustStore writes the trust store to disk with 0600 permissions. The
// parent directory is created with 0700 if missing.
func saveTrustStore(path string, ts *trustStore) error {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("failed to create trust store dir %q: %w", dir, err)
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
		_ = os.Remove(tmpPath)
	}()
	_, err = tmp.Write(b)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write trust store: %w", err)
	}
	err = tmp.Chmod(0o600)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod trust store: %w", err)
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

// checkOrPinAnchor matches the fetched anchor pubkey pair against the trust
// store. On first contact it prompts the user (TTY only) to accept the pin.
// On mismatch it refuses. On match it returns nil.
//
// If confirm is nil, the function never prompts and fails closed on first
// contact; callers pass the terminal confirmer in interactive mode only.
func (ts *trustStore) checkOrPinAnchor(
	server, userID string,
	es384Pub *ecdsa.PublicKey,
	es384Raw json.RawMessage,
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
		// Constant-time comparison on the fingerprint hex (same length on both sides).
		if subtle.ConstantTimeCompare([]byte(entry.Fingerprint), []byte(fp)) != 1 {
			return false, fmt.Errorf(
				"anchor fingerprint mismatch for %s (user %s); pinned=%s, server=%s; refusing to re-pin without explicit operator approval",
				server, userID, entry.Fingerprint, fp,
			)
		}
		// Also check the pubkey components directly, so a bug in fingerprinting
		// cannot mask a real mismatch.
		if entry.AnchorMldsa87PublicKey != mldsa87PubB64 {
			return false, fmt.Errorf("anchor ML-DSA-87 pubkey does not match pin for %s (user %s)", server, userID)
		}

		if !bytesEqualJSON(entry.AnchorEs384PublicKey, es384Raw) {
			return false, fmt.Errorf("anchor ES384 pubkey does not match pin for %s (user %s)", server, userID)
		}

		return false, nil
	}

	// First contact.
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
		AnchorEs384PublicKey:   es384Raw,
		AnchorMldsa87PublicKey: mldsa87PubB64,
		Fingerprint:            fp,
		FirstSeen:              time.Now().UTC(),
	}
	return true, nil
}

// bytesEqualJSON compares two JSON raw messages for byte equality after a
// canonical decode. This avoids spurious mismatches if the server re-orders
// JWK fields between pin-time and now (they should not; but defense-in-depth).
func bytesEqualJSON(a, b json.RawMessage) bool {
	var av, bv any
	errA := json.Unmarshal(a, &av)
	errB := json.Unmarshal(b, &bv)
	if errA != nil || errB != nil {
		return false
	}
	abytes, errA := json.Marshal(av)
	bbytes, errB := json.Marshal(bv)
	if errA != nil || errB != nil {
		return false
	}
	return subtle.ConstantTimeCompare(abytes, bbytes) == 1
}
