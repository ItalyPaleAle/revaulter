package revaulter

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// ErrInvalidSignature is returned by the verify operations when a signature does not match the message
var ErrInvalidSignature = errors.New("signature is not valid")

// SigningKey is a public signing key published on the server
// Keys are only returned after the anchor-signed proof that binds them to the user's pinned anchor has been verified, so a compromised server cannot substitute a key of its choosing
type SigningKey struct {
	// Identifier the server assigned to the key
	ID string
	// Logical label the key belongs to
	KeyLabel string
	// Signing algorithm the key is used with
	Algorithm string
	// KeyID is the RFC 7638 JWK thumbprint of the key, which is the same identifier reported in SignResult.SigningKeyID
	KeyID string
	// Parsed public key: *ecdsa.PublicKey for ES256, ed25519.PublicKey for Ed25519 and Ed25519ph
	PublicKey crypto.PublicKey
	// Raw JWK returned by the server
	JWK json.RawMessage
}

// VerifyRequest is the request for the [Client.Verify] operation
type VerifyRequest struct {
	// Logical label of the key the message was signed with (required for Client.Verify)
	KeyLabel string
	// Signing algorithm the message was signed with (required for Client.Verify)
	Algorithm string
	// Message the signature covers
	// Exactly one of Message or Digest is required
	Message []byte
	// Pre-computed digest of the message: 32 bytes (SHA-256) for ES256, or 64 bytes (SHA-512) for Ed25519ph
	// Ed25519 signatures cover the message itself, so they cannot be verified from a digest
	Digest []byte
	// Signature to verify: 64 bytes, in the IEEE P1363 r||s form for ES256
	Signature []byte
}

// SigningPublicKey retrieves the public signing key published on the server for a key label and algorithm
// Signing keys must be published from the Revaulter web interface: publishing attaches the anchor-signed proof this method verifies before returning the key
// The result can be cached and used with [SigningKey.Verify] to check signatures without contacting the server again
func (c *Client) SigningPublicKey(ctx context.Context, keyLabel string, algorithm string) (*SigningKey, error) {
	keyLabel, err := normalizeKeyLabel(keyLabel)
	if err != nil {
		return nil, err
	}

	algorithm, err = normalizeSigningAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	key, err := c.core.SigningPublicKey(ctx, keyLabel, algorithm)
	if err != nil {
		return nil, err
	}

	return &SigningKey{
		ID:        key.ID,
		KeyLabel:  key.KeyLabel,
		Algorithm: key.Algorithm,
		KeyID:     key.KeyID,
		PublicKey: key.PublicKey,
		JWK:       key.JWK,
	}, nil
}

// Verify checks a signature against the public signing key published on the server for the request's key label and algorithm
// Unlike the other operations, verifying does not require the user's approval: it only fetches a public key, then checks the signature locally
// It returns nil if the signature is valid, or an error wrapping [ErrInvalidSignature] if it is not
func (c *Client) Verify(ctx context.Context, req VerifyRequest) error {
	key, err := c.SigningPublicKey(ctx, req.KeyLabel, req.Algorithm)
	if err != nil {
		return err
	}

	return key.Verify(req)
}

// Verify checks a signature against the public key, locally
// The request's KeyLabel and Algorithm are optional: when set, they must match the key's
// It returns nil if the signature is valid, or an error wrapping [ErrInvalidSignature] if it is not
func (k *SigningKey) Verify(req VerifyRequest) error {
	if k == nil || k.PublicKey == nil {
		return errors.New("missing public key")
	}

	algorithm := k.Algorithm
	if req.Algorithm != "" {
		var err error
		algorithm, err = normalizeSigningAlgorithm(req.Algorithm)
		if err != nil {
			return err
		}

		// Ed25519 and Ed25519ph share the same key material, so the key's algorithm only needs to be compatible, not identical
		if !compatibleSigningAlgorithms(algorithm, k.Algorithm) {
			return fmt.Errorf("key is for algorithm %q, but the signature was requested for %q", k.Algorithm, algorithm)
		}
	}

	if req.KeyLabel != "" {
		keyLabel, err := normalizeKeyLabel(req.KeyLabel)
		if err != nil {
			return err
		}
		if k.KeyLabel != "" && keyLabel != k.KeyLabel {
			return fmt.Errorf("key is for label %q, but the signature was requested for %q", k.KeyLabel, keyLabel)
		}
	}

	if len(req.Signature) != signatureSize {
		return fmt.Errorf("%w: unexpected signature length: got %d bytes, want %d", ErrInvalidSignature, len(req.Signature), signatureSize)
	}

	signingInput, err := resolveSigningInput(algorithm, req.Message, req.Digest)
	if err != nil {
		return err
	}

	switch algorithm {
	case protocolv2.SigningAlgES256:
		pub, ok := k.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not an ECDSA key: %T", k.PublicKey)
		}

		// Signatures are in the IEEE P1363 r||s form
		r := new(big.Int).SetBytes(req.Signature[:32])
		s := new(big.Int).SetBytes(req.Signature[32:])
		if !ecdsa.Verify(pub, signingInput, r, s) {
			return ErrInvalidSignature
		}

	case protocolv2.SigningAlgEd25519:
		pub, ok := k.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not an Ed25519 key: %T", k.PublicKey)
		}

		if !ed25519.Verify(pub, signingInput, req.Signature) {
			return ErrInvalidSignature
		}

	case protocolv2.SigningAlgEd25519ph:
		pub, ok := k.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not an Ed25519 key: %T", k.PublicKey)
		}

		// Ed25519ph verifies the SHA-512 digest of the message
		err = ed25519.VerifyWithOptions(pub, signingInput, req.Signature, &ed25519.Options{Hash: crypto.SHA512})
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
		}

	default:
		return fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}

	return nil
}

// compatibleSigningAlgorithms reports whether a signature made with algorithm a can be verified with a key published for algorithm b
func compatibleSigningAlgorithms(a, b string) bool {
	if a == b || b == "" {
		return true
	}

	// Ed25519 and Ed25519ph use the same key type, and the server stores them as the same JWK
	isEd := func(alg string) bool {
		return alg == protocolv2.SigningAlgEd25519 || alg == protocolv2.SigningAlgEd25519ph
	}

	return isEd(a) && isEd(b)
}
