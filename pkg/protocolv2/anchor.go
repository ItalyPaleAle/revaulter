package protocolv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Domain-separation prefixes for anchor-signed messages
// Every signature the anchor produces must carry one of these literal prefixes; a verifier that accepts a signature without the prefix would let an attacker replay a signature from one context into another
const (
	// #nosec G101 - False positive
	CredAttestPrefix    = "revaulter/v2/cred-attest\n"
	PubkeyBundlePrefix  = "revaulter/v2/pubkey-bundle\n"
	WrappedAnchorAADFmt = "revaulter/v2/wrapped-anchor\nuserId=%s\nv=1"
)

// Fixed sizes for the PQ and classical legs of the hybrid anchor.
const (
	MLDSA87PublicKeySize = mldsa87.PublicKeySize // 2592
	MLDSA87SignatureSize = mldsa87.SignatureSize // 4627

	// ES384SignatureSize is the fixed length of a raw r||s P-384 signature.
	// WebCrypto's ECDSA produces this format (IEEE P1363), so we accept only this
	// on the wire and reject ASN.1-DER encoded signatures.
	ES384SignatureSize = 2 * p384CoordinateSize // 96
)

// AttestationPayload is the canonicalized payload that the anchor signs
// when a new credential is enrolled.
type AttestationPayload struct {
	UserID              string `json:"userId"`
	CredentialID        string `json:"credentialId"`
	CredentialPublicKey string `json:"credentialPublicKey"`
	WrappedKeyEpoch     int64  `json:"wrappedKeyEpoch"`
	CreatedAt           int64  `json:"createdAt"`
}

// PubkeyBundlePayload is the canonicalized payload that the anchor signs
// to bind the user's long-lived transport pubkeys and the anchor pubkeys
// together into a single hybrid-signed bundle.
type PubkeyBundlePayload struct {
	UserID                 string `json:"userId"`
	RequestEncEcdhPubkey   string `json:"requestEncEcdhPubkey"`
	RequestEncMlkemPubkey  string `json:"requestEncMlkemPubkey"`
	AnchorEs384PublicKey   string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string `json:"anchorMldsa87PublicKey"`
	WrappedKeyEpoch        int64  `json:"wrappedKeyEpoch"`
}

// CanonicalAttestationMessage returns the domain-separated, canonically-encoded
// message that both anchor legs (ES384 and ML-DSA-87) sign for credential attestation.
func CanonicalAttestationMessage(payload AttestationPayload) ([]byte, error) {
	body, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize attestation payload: %w", err)
	}
	out := make([]byte, 0, len(CredAttestPrefix)+len(body))
	out = append(out, CredAttestPrefix...)
	out = append(out, body...)
	return out, nil
}

// CanonicalPubkeyBundleMessage returns the domain-separated, canonically-encoded
// bundle message signed by both anchor legs.
func CanonicalPubkeyBundleMessage(payload PubkeyBundlePayload) ([]byte, error) {
	body, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize pubkey bundle payload: %w", err)
	}
	out := make([]byte, 0, len(PubkeyBundlePrefix)+len(body))
	out = append(out, PubkeyBundlePrefix...)
	out = append(out, body...)
	return out, nil
}

// canonicalJSON produces a deterministic JSON encoding of v by going through
// Go's default marshaller with HTML escaping disabled, matching the browser's
// canonical encoding (TextEncoder over JSON.stringify of a fixed-field object).
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return unescapeHTMLJSON(b), nil
}

func unescapeHTMLJSON(b []byte) []byte {
	out := b
	out = bytes.ReplaceAll(out, []byte(`\u003c`), []byte{'<'})
	out = bytes.ReplaceAll(out, []byte(`\u003e`), []byte{'>'})
	out = bytes.ReplaceAll(out, []byte(`\u0026`), []byte{'&'})
	return out
}

// VerifyHybridAttestation verifies that both legs of the hybrid signature
// cover the canonical attestation message. Both must validate; if either
// fails the call returns an error describing which legs rejected the signature.
func VerifyHybridAttestation(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte, payload AttestationPayload, sigEs384, sigMldsa87 []byte) error {
	msg, err := CanonicalAttestationMessage(payload)
	if err != nil {
		return err
	}
	return verifyHybrid(es384Pub, mldsa87PubBytes, msg, sigEs384, sigMldsa87)
}

// VerifyHybridBundle verifies both legs of the hybrid signature covering the
// canonical pubkey-bundle message.
func VerifyHybridBundle(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte, payload PubkeyBundlePayload, sigEs384, sigMldsa87 []byte) error {
	msg, err := CanonicalPubkeyBundleMessage(payload)
	if err != nil {
		return err
	}
	return verifyHybrid(es384Pub, mldsa87PubBytes, msg, sigEs384, sigMldsa87)
}

func verifyHybrid(es384Pub *ecdsa.PublicKey, mldsa87PubBytes, msg, sigEs384, sigMldsa87 []byte) error {
	var errs []error

	err := verifyES384(es384Pub, msg, sigEs384)
	if err != nil {
		errs = append(errs, fmt.Errorf("ES384: %w", err))
	}

	err = verifyMLDSA87(mldsa87PubBytes, msg, sigMldsa87)
	if err != nil {
		errs = append(errs, fmt.Errorf("ML-DSA-87: %w", err))
	}

	return errors.Join(errs...)
}

// verifyES384 accepts a raw IEEE-P1363 r||s signature (as produced by WebCrypto).
// ASN.1-DER-encoded signatures are rejected.
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

// UnmarshalMLDSA87PublicKey decodes a raw ML-DSA-87 public key.
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

// AnchorFingerprint returns the lowercase hex-encoded SHA-256 fingerprint of
// the concatenated anchor public-key pair. This is the value humans compare
// when pinning a server on first contact, and the value mixed into the CLI's
// request-encryption AAD.
//
// The classical leg is canonicalized as its JWK bytes so the fingerprint is
// reproducible from wire-format inputs alone. Each side is length-prefixed
// so that concatenation is unambiguous.
func AnchorFingerprint(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte) (string, error) {
	if es384Pub == nil {
		return "", errors.New("ES384 public key is nil")
	}
	if len(mldsa87PubBytes) != MLDSA87PublicKeySize {
		return "", fmt.Errorf("ML-DSA-87 public key must be %d bytes, got %d", MLDSA87PublicKeySize, len(mldsa87PubBytes))
	}

	jwk, err := ECP384PublicJWKFromECDSA(es384Pub)
	if err != nil {
		return "", err
	}
	jwkBytes, err := canonicalJSON(jwk)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(jwkBytes)))
	h.Write(lenBuf[:])
	h.Write(jwkBytes)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(mldsa87PubBytes)))
	h.Write(lenBuf[:])
	h.Write(mldsa87PubBytes)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// DecodeBase64Signature decodes a base64url-encoded signature of the given size.
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
