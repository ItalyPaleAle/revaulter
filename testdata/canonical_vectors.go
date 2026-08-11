//go:build unit

// Package testdata holds fixtures that are shared across test suites, including across languages
package testdata

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

//go:embed protocol-canonical-vectors.json
var canonicalVectorsJSON []byte

// SigningJwk is the subset of a signing JWK the thumbprint vectors carry
// Y is empty for OKP (Ed25519) keys
type SigningJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type ES384JwkVector struct {
	Name          string                     `json:"name"`
	JWK           protocolv2.ECP384PublicJWK `json:"jwk"`
	CanonicalBody string                     `json:"canonicalBody"`
}

type AttestationVector struct {
	Name          string                        `json:"name"`
	Payload       protocolv2.AttestationPayload `json:"payload"`
	CanonicalBody string                        `json:"canonicalBody"`
	Message       string                        `json:"message"`
}

type PubkeyBundleV2Vector struct {
	Name          string                           `json:"name"`
	Payload       protocolv2.PubkeyBundlePayloadV2 `json:"payload"`
	CanonicalBody string                           `json:"canonicalBody"`
	Message       string                           `json:"message"`
}

type SigningKeyPublicationVector struct {
	Name          string                                  `json:"name"`
	Payload       protocolv2.SigningKeyPublicationPayload `json:"payload"`
	CanonicalBody string                                  `json:"canonicalBody"`
	Message       string                                  `json:"message"`
}

type TransportAadVector struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	Aad       string `json:"aad"`
}

type RequestEncAadVector struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	KeyLabel  string `json:"keyLabel"`
	Operation string `json:"operation"`
	Aad       string `json:"aad"`
}

type JwkThumbprintVector struct {
	Name         string     `json:"name"`
	JWK          SigningJwk `json:"jwk"`
	CanonicalJwk string     `json:"canonicalJwk"`
	Thumbprint   string     `json:"thumbprint"`
}

// CanonicalVectors holds every byte string that the Go and TypeScript implementations must construct identically
// The TypeScript suite in client/web/src/lib/canonical-vectors.test.ts reads the same JSON file, so a change on either side that is not mirrored in the other breaks both test suites rather than silently producing signatures the other cannot verify
type CanonicalVectors struct {
	ES384JwkCanonicalBody []ES384JwkVector              `json:"es384JwkCanonicalBody"`
	Attestation           []AttestationVector           `json:"attestation"`
	PubkeyBundleV2        []PubkeyBundleV2Vector        `json:"pubkeyBundleV2"`
	SigningKeyPublication []SigningKeyPublicationVector `json:"signingKeyPublication"`
	TransportAad          []TransportAadVector          `json:"transportAad"`
	RequestEncAad         []RequestEncAadVector         `json:"requestEncAad"`
	JwkThumbprint         []JwkThumbprintVector         `json:"jwkThumbprint"`
}

// LoadCanonicalVectors parses the embedded shared test vectors
func LoadCanonicalVectors() (CanonicalVectors, error) {
	var v CanonicalVectors
	err := json.Unmarshal(canonicalVectorsJSON, &v)
	if err != nil {
		return CanonicalVectors{}, fmt.Errorf("failed to parse the shared canonical vectors: %w", err)
	}

	return v, nil
}
