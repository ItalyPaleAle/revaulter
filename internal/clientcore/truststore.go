package clientcore

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// TrustStore persists pinned anchor public keys per (server, userId) tuple
// Pinning is TOFU: on first contact the client records both halves of the user's hybrid anchor, and on every subsequent contact the client refuses to proceed if either half does not match the pinned value
// A mismatch is always surfaced as an explicit rotation prompt — the client never silently re-pins
type TrustStore struct {
	Entries map[string]TrustStoreEntry `json:"entries"`
	Path    string                     `json:"-"`
}

// TrustStoreEntry is the per-target record
// The fingerprint is redundant but stable — it's what humans compare when verifying a pin
type TrustStoreEntry struct {
	AnchorEs384PublicKey   string    `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string    `json:"anchorMldsa87PublicKey"`
	Fingerprint            string    `json:"fingerprint"`
	FirstSeen              time.Time `json:"firstSeen"`
}

// TrustStoreKey returns the canonical map key for a (server, userId) pair
// Anchor identity belongs to the user, not to any particular request key that routes traffic to them, so pins survive request-key rotations
func TrustStoreKey(server, userID string) string {
	return server + "|" + userID
}

// DefaultTrustStorePath returns the default path for the trust store
func DefaultTrustStorePath() (string, error) {
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

// ResolveTrustStorePath returns path when it's not empty, or the default trust store path otherwise
func ResolveTrustStorePath(path string) (string, error) {
	if path != "" {
		return path, nil
	}

	return DefaultTrustStorePath()
}

// LoadTrustStore reads the trust store from disk
// A missing file returns an empty store
func LoadTrustStore(path string) (*TrustStore, error) {
	ts := &TrustStore{
		Entries: make(map[string]TrustStoreEntry),
		Path:    path,
	}

	// #nosec G304 -- path is controlled by the user via configuration or DefaultTrustStorePath
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
		ts.Entries = make(map[string]TrustStoreEntry)
	}
	ts.Path = path

	return ts, nil
}

// SaveTrustStore writes the trust store to disk with 0600 permissions
func SaveTrustStore(path string, ts *TrustStore) error {
	// Create the directory with 0700 if missing
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

	// Write atomically via rename to avoid partial writes on crash
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

// CheckOrPinAnchor matches the fetched anchor pubkey pair against the trust store
//
// - On first contact it invokes confirm to accept the pin
// - On mismatch it refuses
// - On match it returns nil
//
// If confirm is nil, the function never prompts and fails closed on first contact
// Callers pass a confirmer in interactive mode only
func (ts *TrustStore) CheckOrPinAnchor(
	server, userID string,
	es384Pub *ecdsa.PublicKey,
	es384Canonical string,
	mldsa87PubB64 string,
	mldsa87PubBytes []byte,
	confirm ConfirmAnchorFunc,
) (pinned bool, err error) {
	fp, err := protocolv2.AnchorFingerprint(es384Pub, mldsa87PubBytes)
	if err != nil {
		return false, fmt.Errorf("compute anchor fingerprint: %w", err)
	}

	key := TrustStoreKey(server, userID)
	entry, ok := ts.Entries[key]
	if ok {
		// Constant-time comparison on the fingerprint hex (same length on both sides)
		if subtle.ConstantTimeCompare([]byte(entry.Fingerprint), []byte(fp)) != 1 {
			return false, fmt.Errorf(
				"anchor fingerprint mismatch for %s (user %s); pinned=%s, server=%s; refusing to re-pin without explicit operator approval%s",
				server, userID, entry.Fingerprint, fp, ts.trustStorePathHint(),
			)
		}

		// Also check the pubkey components directly
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
	accepted, err := confirm(server, userID, fp)
	if err != nil {
		return false, err
	}
	if !accepted {
		return false, errors.New("anchor pin declined by user")
	}
	ts.Entries[key] = TrustStoreEntry{
		AnchorEs384PublicKey:   es384Canonical,
		AnchorMldsa87PublicKey: mldsa87PubB64,
		Fingerprint:            fp,
		FirstSeen:              time.Now().UTC(),
	}
	return true, nil
}

// trustStorePathHint returns an operator hint for anchor rotation errors
func (ts *TrustStore) trustStorePathHint() string {
	if ts.Path == "" {
		return ""
	}

	return "; trust store: " + ts.Path
}

// FormatFingerprint formats a hex fingerprint for display with spaces every 4 chars, newlines every 4 groups of 4, all uppercase
func FormatFingerprint(fp string, prefixSpaces int) string {
	fp = strings.ToUpper(fp)
	var b strings.Builder
	linePrefix := strings.Repeat(" ", prefixSpaces)
	b.WriteString(linePrefix)
	for i, c := range fp {
		if i > 0 && i%4 == 0 {
			if i%16 == 0 {
				b.WriteByte('\n')
				b.WriteString(linePrefix)
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(c)
	}
	return b.String()
}
