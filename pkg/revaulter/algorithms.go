package revaulter

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// Algorithms supported by the encrypt and decrypt operations
const (
	// AlgorithmA256GCM is AES-256-GCM
	AlgorithmA256GCM = "A256GCM"
	// AlgorithmC20P is ChaCha20-Poly1305
	AlgorithmC20P = "C20P"
)

// Algorithms supported by the sign and verify operations
const (
	// AlgorithmES256 is ECDSA using P-256 and SHA-256
	AlgorithmES256 = protocolv2.SigningAlgES256
	// AlgorithmEd25519 is pure Ed25519 (PureEdDSA, RFC 8032)
	AlgorithmEd25519 = protocolv2.SigningAlgEd25519
	// AlgorithmEd25519ph is Ed25519ph (HashEdDSA, RFC 8032, with SHA-512 prehash)
	AlgorithmEd25519ph = protocolv2.SigningAlgEd25519ph
)

// validateEncryptionAlgorithm checks that the algorithm is one the server accepts for encrypt and decrypt operations
func validateEncryptionAlgorithm(algorithm string) error {
	if algorithm == "" {
		return errors.New("algorithm is required")
	}
	if !protocolv2.IsSupportedEncryptionAlgorithm(algorithm) {
		return fmt.Errorf("unsupported encryption algorithm %q: expected %q or %q", algorithm, AlgorithmA256GCM, AlgorithmC20P)
	}

	return nil
}

// normalizeSigningAlgorithm returns the canonical form of a supported signing algorithm
// All downstream consumers (HKDF info, AAD, JWS headers) use the canonical form, so the same string flows through every layer
func normalizeSigningAlgorithm(algorithm string) (string, error) {
	if algorithm == "" {
		return "", errors.New("algorithm is required")
	}

	canonical, ok := protocolv2.NormalizeSigningAlgorithm(algorithm)
	if !ok {
		return "", fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}

	return canonical, nil
}

// resolveSigningInput returns the bytes a signature covers for the given algorithm
// ES256 and Ed25519ph sign a digest of the message, which the caller can also supply pre-computed; Ed25519 signs the message itself
func resolveSigningInput(algorithm string, message []byte, digest []byte) ([]byte, error) {
	switch {
	case len(message) > 0 && len(digest) > 0:
		return nil, errors.New("message and digest are mutually exclusive")
	case len(message) == 0 && len(digest) == 0:
		return nil, errors.New("one of message or digest is required")
	}

	if len(digest) > 0 {
		switch algorithm {
		case protocolv2.SigningAlgES256:
			if len(digest) != sha256.Size {
				return nil, fmt.Errorf("invalid digest length for %s: expected %d bytes, got %d", algorithm, sha256.Size, len(digest))
			}
		case protocolv2.SigningAlgEd25519ph:
			if len(digest) != sha512.Size {
				return nil, fmt.Errorf("invalid digest length for %s: expected %d bytes, got %d", algorithm, sha512.Size, len(digest))
			}
		case protocolv2.SigningAlgEd25519:
			return nil, errors.New("digest is not supported for Ed25519: pass the message so the raw bytes can be signed")
		default:
			return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
		}

		return digest, nil
	}

	switch algorithm {
	case protocolv2.SigningAlgES256:
		// ECDSA with P-256 uses SHA-256
		sum := sha256.Sum256(message)
		return sum[:], nil

	case protocolv2.SigningAlgEd25519:
		// With Ed25519, the message is hashed during the signing process
		return message, nil

	case protocolv2.SigningAlgEd25519ph:
		// Ed25519 pre-hashed uses SHA-512
		sum := sha512.Sum512(message)
		return sum[:], nil

	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
}
