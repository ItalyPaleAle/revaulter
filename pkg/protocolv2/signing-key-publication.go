package protocolv2

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"
)

// SigningKeyPublicationPrefix is the domain-separation tag for anchor-signed signing-key publication proofs
// A verifier that accepts a signature without the prefix would let an attacker replay a signature from one context into another
const SigningKeyPublicationPrefix = "revaulter/v2/signing-key-publication\n"

// SigningKeyPublicationVersion is the only `v` value the verifier accepts today
// Bump when the canonical body shape changes in a backwards-incompatible way
const SigningKeyPublicationVersion int64 = 1

// SigningKeyPublicationPayload is the canonicalized payload the anchor signs to authorize publishing a derived signing key
// The order is load-bearing: client and server must produce identical bytes
// keyId is the JWK thumbprint already used as the row id, so the proof binds to a single canonical identifier and the server cross-checks the JWK/PEM in validateSigningJWKAndPEM
type SigningKeyPublicationPayload struct {
	UserID          string `key:"userId"`
	Algorithm       string `key:"algorithm"`
	KeyLabel        string `key:"keyLabel"`
	KeyID           string `key:"keyId"`
	WrappedKeyEpoch int64  `key:"wrappedKeyEpoch"`
	CreatedAt       int64  `key:"createdAt"`
	V               int64  `key:"v"`
}

// CanonicalBody encodes the publication payload as ordered key=value lines separated by '\n', with no trailing newline
// Reuses the shared canonicalBodyFromTaggedFields helper, which already supports the string and int64 field kinds used here
// The helper expects a struct value, so we dereference the receiver before passing it in
func (p SigningKeyPublicationPayload) CanonicalBody() string {
	return canonicalBodyFromTaggedFields(p)
}

// ValidateCreatedAt rejects publication payloads whose `createdAt` is outside `[now-skew, now+skew]`
// The signed `createdAt` is one of the few non-replay defenses: an attacker who exfiltrated a proof from logs/backups could otherwise re-submit it later under the same (userId, keyId, epoch) and have the verifier accept the canonical bytes
// Once a row is stored as proven, this skew check is NOT re-evaluated on subsequent publish/unpublish toggles
func (p SigningKeyPublicationPayload) ValidateCreatedAt(now time.Time, skew time.Duration) error {
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

// ParseSigningKeyPublicationPayload parses a canonical body string back into a SigningKeyPublicationPayload
// The input must list every expected key in the documented order, exactly once, separated by '\n', with no trailing newline
func ParseSigningKeyPublicationPayload(body string) (SigningKeyPublicationPayload, error) {
	var p SigningKeyPublicationPayload
	err := parseTaggedFields(body, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}

// CanonicalSigningKeyPublicationMessage returns the domain-separated, canonically-encoded message that both anchor legs sign for a publication proof
func CanonicalSigningKeyPublicationMessage(payload *SigningKeyPublicationPayload) []byte {
	body := payload.CanonicalBody()
	out := make([]byte, len(SigningKeyPublicationPrefix)+len(body))
	copy(out[0:len(SigningKeyPublicationPrefix)], SigningKeyPublicationPrefix)
	copy(out[len(SigningKeyPublicationPrefix):], body)
	return out
}

// VerifyHybridSigningKeyPublication verifies that both legs of the hybrid signature cover the canonical publication message
// Both must validate; if either fails the call returns an error describing which legs rejected the signature
//
// SECURITY: This is a consistency check between the supplied pubkeys, payload, and signatures
// It does NOT by itself establish trust in the anchor pubkeys or in the payload's bindings
// Callers MUST independently bind the anchor pubkeys to the principal they represent (e.g., by comparing them against values pinned at registration time) AND cross-check payload fields (UserID, KeyID, Algorithm, KeyLabel, WrappedKeyEpoch, V) against an independent source of truth before trusting the publication claim
func VerifyHybridSigningKeyPublication(es384Pub *ecdsa.PublicKey, mldsa87PubBytes []byte, payload *SigningKeyPublicationPayload, sigEs384, sigMldsa87 []byte) error {
	msg := CanonicalSigningKeyPublicationMessage(payload)
	return verifyHybrid(es384Pub, mldsa87PubBytes, msg, sigEs384, sigMldsa87)
}

// SigningKeyPublicResponseVerifyOptions captures everything an external client (CLI, third-party tool) needs to verify a `.jwk`/`.json` response from /v2/signing-keys/:filename
//
// `Es384Pub` and `Mldsa87PubBytes` MUST come from a trusted source (typically the CLI's pinned anchor) — NOT from the response — otherwise verification proves only that the holder of the response-side keys signed the body, which an attacker could supply
type SigningKeyPublicResponseVerifyOptions struct {
	// Pinned anchor public keys (from the trust store / out-of-band channel)
	Es384Pub        *ecdsa.PublicKey
	Mldsa87PubBytes []byte

	// Expected payload bindings — typically the user the caller is talking to and the key they expected to fetch
	// An empty value here means "do not check" and weakens the verification, so callers should always populate every field they have an expectation for
	ExpectedUserID    string
	ExpectedAlgorithm string
	ExpectedKeyID     string
}

// VerifySigningKeyPublicResponse verifies an anchor-signed publication proof on a public response and cross-checks the canonical payload against caller-supplied expected values
// Returns the parsed payload on success; callers may use it for logging or further inspection
func VerifySigningKeyPublicResponse(payloadStr string, sigEsB64, sigMlB64 string, opts SigningKeyPublicResponseVerifyOptions) (SigningKeyPublicationPayload, error) {
	if payloadStr == "" || sigEsB64 == "" || sigMlB64 == "" {
		return SigningKeyPublicationPayload{}, errors.New("response is missing the publication proof")
	}
	if opts.Es384Pub == nil {
		return SigningKeyPublicationPayload{}, errors.New("pinned ES384 anchor public key is required")
	}
	if len(opts.Mldsa87PubBytes) != MLDSA87PublicKeySize {
		return SigningKeyPublicationPayload{}, fmt.Errorf("pinned ML-DSA-87 anchor public key must be %d bytes, got %d", MLDSA87PublicKeySize, len(opts.Mldsa87PubBytes))
	}

	// Parse the payload and validate it
	payload, err := ParseSigningKeyPublicationPayload(payloadStr)
	if err != nil {
		return SigningKeyPublicationPayload{}, fmt.Errorf("invalid publication body: %w", err)
	}

	if payload.V != SigningKeyPublicationVersion {
		return SigningKeyPublicationPayload{}, fmt.Errorf("unsupported publication version %d", payload.V)
	}
	if opts.ExpectedUserID != "" && payload.UserID != opts.ExpectedUserID {
		return SigningKeyPublicationPayload{}, fmt.Errorf("publication userId %q does not match expected %q", payload.UserID, opts.ExpectedUserID)
	}
	if opts.ExpectedAlgorithm != "" && payload.Algorithm != opts.ExpectedAlgorithm {
		return SigningKeyPublicationPayload{}, fmt.Errorf("publication algorithm %q does not match expected %q", payload.Algorithm, opts.ExpectedAlgorithm)
	}
	if opts.ExpectedKeyID != "" && payload.KeyID != opts.ExpectedKeyID {
		return SigningKeyPublicationPayload{}, fmt.Errorf("publication keyId %q does not match expected %q", payload.KeyID, opts.ExpectedKeyID)
	}

	// Decode the signatures
	sigEs, err := DecodeBase64Signature(sigEsB64, ES384SignatureSize)
	if err != nil {
		return SigningKeyPublicationPayload{}, fmt.Errorf("publicationSignatureEs384: %w", err)
	}
	sigMl, err := DecodeBase64Signature(sigMlB64, MLDSA87SignatureSize)
	if err != nil {
		return SigningKeyPublicationPayload{}, fmt.Errorf("publicationSignatureMldsa87: %w", err)
	}

	// Validate the signatures
	err = VerifyHybridSigningKeyPublication(opts.Es384Pub, opts.Mldsa87PubBytes, &payload, sigEs, sigMl)
	if err != nil {
		return SigningKeyPublicationPayload{}, fmt.Errorf("signature verification failed: %w", err)
	}

	return payload, nil
}
