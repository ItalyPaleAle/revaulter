package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils"
)

// Constructs the AAD that the browser binds into the AES-GCM tag during encryption
func buildTransportAAD(state, operation, algorithm string) []byte {
	// Keep the transport AAD serialization deterministic and independent from JSON key ordering so browser and CLI always bind the same AES-GCM tag bytes
	return fmt.Appendf(nil, "algorithm=%s\noperation=%s\nstate=%s\nv=1", algorithm, operation, state)
}

// buildRequestEncAAD constructs the AAD used when encrypting/decrypting request payloads.
// It binds the plaintext metadata to the E2EE ciphertext.
func buildRequestEncAAD(algorithm, keyLabel, operation string) []byte {
	return fmt.Appendf(nil, "algorithm=%s\nkeyLabel=%s\noperation=%s\nv=1", algorithm, keyLabel, operation)
}

func decryptV2ResponseEnvelope(state string, priv *ecdh.PrivateKey, env *protocolv2.ResponseEnvelope, aad []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("missing client transport private key")
	}
	if env == nil {
		return nil, errors.New("missing responseEnvelope")
	}

	err := validateV2EnvelopeForCLI(env)
	if err != nil {
		return nil, err
	}

	peerPub, err := env.BrowserEphemeralPublicKey.ToECDHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid browserEphemeralPublicKey: %w", err)
	}
	sharedSecret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("failed ECDH: %w", err)
	}

	key, err := deriveV2TransportKey(sharedSecret, state)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := utils.DecodeBase64String(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce: bad size")
	}

	ciphertext, err := utils.DecodeBase64String(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}
	return plain, nil
}

func deriveV2TransportKey(sharedSecret []byte, state string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, nil, "revaulter/v2/transport/"+state, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive transport key: %w", err)
	}
	return key, nil
}

func validateV2EnvelopeForCLI(env *protocolv2.ResponseEnvelope) error {
	if env.TransportAlg != "ecdh-p256+a256gcm" {
		return fmt.Errorf("unsupported transportAlg: %s", env.TransportAlg)
	}

	err := env.BrowserEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return err
	}

	return nil
}

func formatV2DecryptedPayload(state string, plain []byte) (json.RawMessage, error) {
	var v any
	if json.Unmarshal(plain, &v) == nil && json.Valid(plain) {
		return json.RawMessage(plain), nil
	}

	// Fallback: bytes -> JSON object with base64 payload
	out := map[string]any{
		"state": state,
		"data":  base64.RawStdEncoding.EncodeToString(plain),
	}

	b, err := json.Marshal(out)
	return json.RawMessage(b), err
}

// encryptV2RequestPayload encrypts the inner request payload using static-ephemeral ECDH.
// The CLI generates an ephemeral key pair, performs ECDH with the browser user's
// static public key, derives an AES-256-GCM key via HKDF, and encrypts the payload.
func encryptV2RequestPayload(
	peerStaticPub *ecdh.PublicKey,
	payload protocolv2.RequestPayloadInner,
	aad []byte,
) (cliEphPub protocolv2.ECP256PublicJWK, nonceB64 string, ciphertextB64 string, err error) {
	// Generate ephemeral ECDH key pair
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return cliEphPub, "", "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	cliEphPub, err = protocolv2.ECP256PublicJWKFromECDH(ephPriv.PublicKey())
	if err != nil {
		return cliEphPub, "", "", fmt.Errorf("failed to export ephemeral public key: %w", err)
	}

	// ECDH shared secret
	sharedSecret, err := ephPriv.ECDH(peerStaticPub)
	if err != nil {
		return cliEphPub, "", "", fmt.Errorf("failed ECDH: %w", err)
	}

	// HKDF to derive AES-256-GCM key
	aesKey, err := hkdf.Key(sha256.New, sharedSecret, nil, "revaulter/v2/request-enc", 32)
	if err != nil {
		return cliEphPub, "", "", fmt.Errorf("failed to derive request encryption key: %w", err)
	}

	// AES-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return cliEphPub, "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cliEphPub, "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return cliEphPub, "", "", err
	}

	// Serialize payload to JSON
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return cliEphPub, "", "", fmt.Errorf("failed to serialize payload: %w", err)
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad)

	nonceB64 = base64.RawURLEncoding.EncodeToString(nonce)
	ciphertextB64 = base64.RawURLEncoding.EncodeToString(ct)
	return cliEphPub, nonceB64, ciphertextB64, nil
}
