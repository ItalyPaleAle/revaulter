package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils"
)

func decryptV2ResponseEnvelope(state string, priv *ecdh.PrivateKey, env *protocolv2.ResponseEnvelope) ([]byte, error) {
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

	var aad []byte
	if env.AAD != "" {
		aad, err = utils.DecodeBase64String(env.AAD)
		if err != nil {
			return nil, fmt.Errorf("invalid aad: %w", err)
		}
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
