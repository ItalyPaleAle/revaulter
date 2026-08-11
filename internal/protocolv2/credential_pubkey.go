package protocolv2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// CredentialPublicKeyHash returns base64url(SHA-256(raw COSE credential public-key bytes))
// The hash is taken over the exact CBOR bytes the authenticator wrote into authData so it is a stable cross-language identifier for any WebAuthn key type, including future post-quantum algorithms
// Both browser and server hash the same bytes, so no per-algorithm serialization is needed on either side
func CredentialPublicKeyHash(coseBytes []byte) (string, error) {
	if len(coseBytes) == 0 {
		return "", errors.New("COSE public key is empty")
	}

	sum := sha256.Sum256(coseBytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// CredentialPublicKeyHashFromStoredCredJSON reads a stored credJSON blob (go-webauthn Credential marshaled as JSON) and returns the credential-public-key hash derived from its `publicKey` field, which holds the raw COSE bytes
func CredentialPublicKeyHashFromStoredCredJSON(credJSON string) (string, error) {
	cose, err := extractStoredCredentialCOSE(credJSON)
	if err != nil {
		return "", err
	}

	return CredentialPublicKeyHash(cose)
}

func extractStoredCredentialCOSE(credJSON string) ([]byte, error) {
	if credJSON == "" {
		return nil, errors.New("stored credJSON is empty")
	}

	var parsed struct {
		PublicKey []byte `json:"publicKey"`
	}
	err := json.Unmarshal([]byte(credJSON), &parsed)
	if err != nil {
		return nil, fmt.Errorf("parse stored credJSON: %w", err)
	}

	if len(parsed.PublicKey) == 0 {
		return nil, errors.New("stored credJSON is missing publicKey")
	}

	return parsed.PublicKey, nil
}
