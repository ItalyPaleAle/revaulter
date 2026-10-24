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

type DevicePublicKeysVector struct {
	Name          string                      `json:"name"`
	Keys          protocolv2.DevicePublicKeys `json:"keys"`
	CanonicalBody string                      `json:"canonicalBody"`
	Hash          string                      `json:"hash"`
}

type AttestationV2Vector struct {
	Name          string                          `json:"name"`
	Payload       protocolv2.AttestationPayloadV2 `json:"payload"`
	CanonicalBody string                          `json:"canonicalBody"`
	Message       string                          `json:"message"`
}

type DeviceLoginVector struct {
	Name          string                        `json:"name"`
	Payload       protocolv2.DeviceLoginPayload `json:"payload"`
	CanonicalBody string                        `json:"canonicalBody"`
	Message       string                        `json:"message"`
}

type DeviceUnlockInfoVector struct {
	Name         string `json:"name"`
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
	EphPub       string `json:"ephPub"`
	KemCt        string `json:"kemCt"`
	Info         string `json:"info"`
}

type PairingPayloadVector struct {
	Name          string                    `json:"name"`
	Payload       protocolv2.PairingPayload `json:"payload"`
	CanonicalBody string                    `json:"canonicalBody"`
	Text          string                    `json:"text"`
	Link          string                    `json:"link"`
}

type PairingMACKeyVector struct {
	Name      string `json:"name"`
	Secret    string `json:"secret"`
	SessionID string `json:"sessionId"`
	Info      string `json:"info"`
	MACKey    string `json:"macKey"`
}

type PairingTranscriptVector struct {
	Name       string                       `json:"name"`
	Transcript protocolv2.PairingTranscript `json:"transcript"`
	Message    string                       `json:"message"`
	MACKey     string                       `json:"macKey"`
	MAC        string                       `json:"mac"`
}

type PairingNonceVector struct {
	Name    string                         `json:"name"`
	Payload protocolv2.PairingNoncePayload `json:"payload"`
	Message string                         `json:"message"`
	MACKey  string                         `json:"macKey"`
	MAC     string                         `json:"mac"`
	Code    string                         `json:"code"`
}

// CanonicalVectors holds every byte string that the Go and TypeScript implementations must construct identically
// The TypeScript suite in client/web/src/lib/canonical-vectors.test.ts reads the same JSON file, so a change on either side that is not mirrored in the other breaks both test suites rather than silently producing signatures the other cannot verify
// The device credential and pairing sections are asserted only by Go until the web client implements pairing
type CanonicalVectors struct {
	ES384JwkCanonicalBody []ES384JwkVector              `json:"es384JwkCanonicalBody"`
	Attestation           []AttestationVector           `json:"attestation"`
	PubkeyBundleV2        []PubkeyBundleV2Vector        `json:"pubkeyBundleV2"`
	SigningKeyPublication []SigningKeyPublicationVector `json:"signingKeyPublication"`
	TransportAad          []TransportAadVector          `json:"transportAad"`
	RequestEncAad         []RequestEncAadVector         `json:"requestEncAad"`
	JwkThumbprint         []JwkThumbprintVector         `json:"jwkThumbprint"`

	DevicePublicKeys  []DevicePublicKeysVector  `json:"devicePublicKeys"`
	AttestationV2     []AttestationV2Vector     `json:"attestationV2"`
	DeviceLogin       []DeviceLoginVector       `json:"deviceLogin"`
	DeviceUnlockInfo  []DeviceUnlockInfoVector  `json:"deviceUnlockInfo"`
	PairingPayload    []PairingPayloadVector    `json:"pairingPayload"`
	PairingMACKey     []PairingMACKeyVector     `json:"pairingMacKey"`
	PairingTranscript []PairingTranscriptVector `json:"pairingTranscript"`
	PairingNonce      []PairingNonceVector      `json:"pairingNonce"`
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
