package protocolv2

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// CredAttestPrefix and PubkeyBundlePrefix are domain-separation prefixes for anchor-signed messages
// Every signature the anchor produces must carry one of these literal prefixes
// A verifier that accepts a signature without the prefix would let an attacker replay a signature from one context into another
const (
	CredAttestPrefix    = "revaulter/v2/cred-attest\n" // #nosec G101 -- domain-separation tag, not a credential
	PubkeyBundlePrefix  = "revaulter/v2/pubkey-bundle\n"
	WrappedAnchorAADFmt = "revaulter/v2/wrapped-anchor\nuserId=%s\nv=1"
)

// Fixed sizes for the PQ and classical legs of the hybrid anchor
const (
	MLDSA87PublicKeySize = mldsa87.PublicKeySize // 2592
	MLDSA87SignatureSize = mldsa87.SignatureSize // 4627

	// ES384SignatureSize is the fixed length of a raw r||s P-384 signature
	// WebCrypto's ECDSA produces this format (IEEE P1363), so we accept only this on the wire and reject ASN.1-DER encoded signatures
	ES384SignatureSize = 2 * p384CoordinateSize // 96
)

// AttestationPayload is the canonicalized payload that the anchor signs when a new credential is enrolled
// The order is load-bearing: client and server must produce identical bytes
type AttestationPayload struct {
	UserID                  string `key:"userId"`
	CredentialID            string `key:"credentialId"`
	CredentialPublicKeyHash string `key:"credentialPublicKeyHash"`
	WrappedKeyEpoch         int64  `key:"wrappedKeyEpoch"`
	CreatedAt               int64  `key:"createdAt"`
}

// CanonicalBody encodes the attestation payload as ordered key=value lines separated by '\n', with no trailing newline
// This is the format stored in the database and sent on the wire
func (p AttestationPayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// ValidateCreatedAt rejects attestation payloads whose `createdAt` is outside `[now-skew, now+skew]`
// The signed `CreatedAt` is one of the few non-replay defenses we have: an attacker who captured a signed attestation could otherwise re-submit it later under the same `(userId, credentialId, hash, epoch)` and have the verifier accept the canonical bytes
// In practice, attacks of this kind are unlikely, but this offers an extra layer of protection
func (p AttestationPayload) ValidateCreatedAt(now time.Time, skew time.Duration) error {
	if skew <= 0 {
		return errors.New("skew must be positive")
	}
	if p.CreatedAt <= 0 {
		return fmt.Errorf("createdAt is missing or non-positive: %d", p.CreatedAt)
	}

	created := time.Unix(p.CreatedAt, 0)
	delta := now.Sub(created)
	if delta < -skew || delta > skew {
		return fmt.Errorf("createdAt %d is outside the ±%s acceptance window of server time", p.CreatedAt, skew)
	}

	return nil
}

// ParseAttestationPayload parses a canonical body string back into an AttestationPayload
// The input must list every expected key in the documented order, exactly once, separated by '\n', with no trailing newline
func ParseAttestationPayload(body string) (AttestationPayload, error) {
	var p AttestationPayload
	err := parseTaggedFields(body, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}

// PubkeyBundlePayload is the canonicalized payload that the anchor signs to bind the user's long-lived transport pubkeys and the anchor pubkeys together into a single hybrid-signed bundle
// The order is load-bearing: client and server must produce identical bytes
// The ES384 anchor pubkey is flattened to its JWK members (crv, kty, x, y) so every field stays on a single line, consistent with every other key=value canonical body in this codebase
type PubkeyBundlePayload struct {
	UserID                 string `key:"userId"`
	RequestEncEcdhPubkey   string `key:"requestEncEcdhPubkey"`
	RequestEncMlkemPubkey  string `key:"requestEncMlkemPubkey"`
	AnchorEs384Crv         string `key:"anchorEs384Crv"`
	AnchorEs384Kty         string `key:"anchorEs384Kty"`
	AnchorEs384X           string `key:"anchorEs384X"`
	AnchorEs384Y           string `key:"anchorEs384Y"`
	AnchorMldsa87PublicKey string `key:"anchorMldsa87PublicKey"`
	WrappedKeyEpoch        int64  `key:"wrappedKeyEpoch"`
}

// CanonicalBody encodes the pubkey-bundle payload as ordered key=value lines separated by '\n', with no trailing newline
// This is the body that (with the domain-separation prefix) is signed by both anchor legs
func (p PubkeyBundlePayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

func canonicalBodyFromTaggedFields(payload any) string {
	var b strings.Builder
	v := reflect.ValueOf(payload)
	t := v.Type()

	for i := range t.NumField() {
		if i > 0 {
			b.WriteByte('\n')
		}

		fieldType := t.Field(i)
		key := fieldType.Tag.Get("key")
		if key == "" {
			// Indicates a development-time error
			panic(fmt.Sprintf("protocolv2: field %s is missing key tag", fieldType.Name))
		}

		b.WriteString(key)
		b.WriteByte('=')

		fieldValue := v.Field(i)
		switch fieldValue.Kind() {
		case reflect.String:
			b.WriteString(fieldValue.String())
		case reflect.Int64:
			b.WriteString(strconv.FormatInt(fieldValue.Int(), 10))
		default:
			// Indicates a development-time error
			panic(fmt.Sprintf("protocolv2: field %s has unsupported kind %s", fieldType.Name, fieldValue.Kind()))
		}
	}

	return b.String()
}

// ParsePubkeyBundlePayload parses a canonical body string back into a PubkeyBundlePayload
// The input must list every expected key in the documented order, exactly once, separated by '\n', with no trailing newline
func ParsePubkeyBundlePayload(body string) (PubkeyBundlePayload, error) {
	var p PubkeyBundlePayload
	err := parseTaggedFields(body, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}

func parseTaggedFields(body string, out any) error {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		panic("protocolv2: parseTaggedFields expects a pointer to a struct")
	}

	v = v.Elem()
	t := v.Type()
	lines := strings.Split(body, "\n")
	if len(lines) != t.NumField() {
		return fmt.Errorf("expected %d lines, got %d", t.NumField(), len(lines))
	}

	for i, line := range lines {
		fieldType := t.Field(i)
		expectedKey := fieldType.Tag.Get("key")
		if expectedKey == "" {
			panic(fmt.Sprintf("protocolv2: field %s is missing key tag", fieldType.Name))
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d missing '='", i)
		}
		if key != expectedKey {
			return fmt.Errorf("line %d: expected key %q, got %q", i, expectedKey, key)
		}

		fieldValue := v.Field(i)
		switch fieldValue.Kind() {
		case reflect.String:
			fieldValue.SetString(value)
		case reflect.Int64:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("%s: %w", expectedKey, err)
			}
			fieldValue.SetInt(n)
		default:
			panic(fmt.Sprintf("protocolv2: field %s has unsupported kind %s", fieldType.Name, fieldValue.Kind()))
		}
	}

	return nil
}

// CanonicalAttestationMessage returns the domain-separated, canonically-encoded message that both anchor legs (ES384 and ML-DSA-87) sign for credential attestation
func CanonicalAttestationMessage(payload *AttestationPayload) []byte {
	body := payload.CanonicalBody()
	out := make([]byte, len(CredAttestPrefix)+len(body))
	copy(out[0:len(CredAttestPrefix)], CredAttestPrefix)
	copy(out[len(CredAttestPrefix):], body)
	return out
}

// CanonicalPubkeyBundleMessage returns the domain-separated, canonically-encoded bundle message signed by both anchor legs
func CanonicalPubkeyBundleMessage(payload *PubkeyBundlePayload) []byte {
	body := payload.CanonicalBody()
	out := make([]byte, len(PubkeyBundlePrefix)+len(body))
	copy(out[0:len(PubkeyBundlePrefix)], PubkeyBundlePrefix)
	copy(out[len(PubkeyBundlePrefix):], body)
	return out
}

// VerifyHybridAttestation verifies that both legs of the hybrid signature cover the canonical attestation message
// Both must validate; if either fails the call returns an error describing which legs rejected the signature
//
// SECURITY: This is a consistency check between the supplied pubkeys, payload, and signatures
// It does NOT by itself establish trust in the anchor pubkeys or in the payload's bindings
// Callers MUST independently verify that the anchor pubkeys belong to the expected principal (for example, by matching them against values stored at registration time) AND cross-check the payload fields (UserID, CredentialID, CredentialPublicKeyHash, ...) against an independent source of truth
// Without those checks an attacker can present attacker-controlled pubkeys and signatures that verify consistently but bind to nothing the server trusts
func VerifyHybridAttestation(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte, payload *AttestationPayload, sigEs384, sigMldsa87 []byte) error {
	msg := CanonicalAttestationMessage(payload)
	return verifyHybrid(es384Pub, mldsa87PubBytes, msg, sigEs384, sigMldsa87)
}

// VerifyHybridBundle verifies both legs of the hybrid signature covering the canonical pubkey-bundle message
//
// SECURITY: This is a consistency check only - it proves that the holder of both anchor private keys
// produced the bundle, but it does NOT establish trust in those pubkeys
// In a self-signed bundle (like the one submitted during signup) the signer's pubkeys are chosen by the caller, so a successful verification only confirms internal consistency
// Callers MUST independently bind the anchor pubkeys to the principal they represent (e.g., by pinning them at registration and comparing on subsequent use) before trusting the payload.
func VerifyHybridBundle(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte, payload *PubkeyBundlePayload, sigEs384 []byte, sigMldsa87 []byte) error {
	msg := CanonicalPubkeyBundleMessage(payload)
	return verifyHybrid(es384Pub, mldsa87PubBytes, msg, sigEs384, sigMldsa87)
}

func verifyHybrid(es384Pub *ecdsa.PublicKey, mldsa87PubBytes, msg, sigEs384, sigMldsa87 []byte) error {
	esErr := verifyES384(es384Pub, msg, sigEs384)
	mlErr := verifyMLDSA87(mldsa87PubBytes, msg, sigMldsa87)
	if esErr == nil && mlErr == nil {
		return nil
	}

	var errs []error
	if esErr != nil {
		errs = append(errs, fmt.Errorf("ES384: %w", esErr))
	}
	if mlErr != nil {
		errs = append(errs, fmt.Errorf("ML-DSA-87: %w", mlErr))
	}
	return errors.Join(errs...)
}

// verifyES384 accepts a raw IEEE-P1363 r||s signature (as produced by WebCrypto) ASN.1-DER-encoded signatures are rejected
func verifyES384(pub *ecdsa.PublicKey, msg, sig []byte) error {
	if pub == nil {
		return errors.New("public key is nil")
	}

	if len(sig) != ES384SignatureSize {
		return fmt.Errorf("signature has wrong length %d, expected %d", len(sig), ES384SignatureSize)
	}

	r := new(big.Int).SetBytes(sig[:p384CoordinateSize])
	s := new(big.Int).SetBytes(sig[p384CoordinateSize:])
	digest := sha512.Sum384(msg)

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("signature verification failed")
	}

	return nil
}

func verifyMLDSA87(pubBytes, msg, sig []byte) error {
	pub, err := UnmarshalMLDSA87PublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	if len(sig) != MLDSA87SignatureSize {
		return fmt.Errorf("signature has wrong length %d, expected %d", len(sig), MLDSA87SignatureSize)
	}

	if !mldsa87.Verify(pub, msg, nil, sig) {
		return errors.New("signature verification failed")
	}

	return nil
}

// UnmarshalMLDSA87PublicKey decodes a raw ML-DSA-87 public key
func UnmarshalMLDSA87PublicKey(b []byte) (*mldsa87.PublicKey, error) {
	if len(b) != MLDSA87PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", MLDSA87PublicKeySize, len(b))
	}

	pk := new(mldsa87.PublicKey)
	err := pk.UnmarshalBinary(b)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return pk, nil
}

// AnchorFingerprint returns the lowercase hex-encoded SHA-256 fingerprint of the concatenated anchor public-key pair
// This is the value humans compare when pinning a server on first contact, and the value mixed into the CLI's request-encryption AAD
// The classical leg is encoded as its SEC1 uncompressed point bytes (0x04 || X || Y, 97 bytes); both legs have fixed sizes so plain concatenation is unambiguous
func AnchorFingerprint(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte) (string, error) {
	if es384Pub == nil {
		return "", errors.New("ES384 public key is nil")
	}
	if len(mldsa87PubBytes) != MLDSA87PublicKeySize {
		return "", fmt.Errorf("ML-DSA-87 public key must be %d bytes, got %d", MLDSA87PublicKeySize, len(mldsa87PubBytes))
	}

	es384Bytes, err := es384Pub.Bytes()
	if err != nil {
		return "", fmt.Errorf("encode ES384 public key: %w", err)
	}
	if len(es384Bytes) != 1+2*p384CoordinateSize {
		return "", fmt.Errorf("unexpected ES384 uncompressed point length %d", len(es384Bytes))
	}

	h := sha256.New()
	h.Write(es384Bytes)
	h.Write(mldsa87PubBytes)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// DecodeBase64Signature decodes a base64url-encoded signature of the given size
// Signatures on the wire are always base64url (raw, no padding).
func DecodeBase64Signature(s string, expectedSize int) ([]byte, error) {
	if s == "" {
		return nil, errors.New("signature is empty")
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	if expectedSize > 0 && len(b) != expectedSize {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectedSize, len(b))
	}
	return b, nil
}
