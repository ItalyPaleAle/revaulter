package revaulter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// EncryptRequest is the request for the [Client.Encrypt] operation
type EncryptRequest struct {
	// Logical label of the key used to encrypt the message (required)
	KeyLabel string
	// Encryption algorithm, such as AlgorithmA256GCM (required)
	Algorithm string
	// Message to encrypt (required)
	// Messages are limited to MaxPayloadSize bytes
	Plaintext []byte
	// Optional additional authenticated data, which is not encrypted but is bound to the ciphertext
	AdditionalData []byte

	// Optional timeout for the operation, which overrides the client's default
	Timeout time.Duration
	// Optional note displayed to the user alongside the request, which overrides the client's default
	Note string
}

// EncryptResult is the result of the [Client.Encrypt] operation
type EncryptResult struct {
	// Logical label of the key the message was encrypted with
	KeyLabel string
	// Algorithm the message was encrypted with
	Algorithm string
	// Encrypted message
	Ciphertext []byte
	// Nonce (or IV) used to encrypt the message
	Nonce []byte
	// Authentication tag
	Tag []byte
	// Additional authenticated data bound to the ciphertext, if any
	AdditionalData []byte
	// Identifier the server assigned to the request that produced this result
	State string
}

// encryptResponsePayload is the JSON shape produced by the browser after encrypting
type encryptResponsePayload struct {
	State          string `json:"state"`
	Operation      string `json:"operation"`
	Algorithm      string `json:"algorithm"`
	Value          string `json:"value"`
	Nonce          string `json:"nonce"`
	Tag            string `json:"tag"`
	AdditionalData string `json:"additionalData"`
}

// Encrypt encrypts a message with a key held by the user, after they approve the request in their browser
// The call blocks until the user approves or denies the request, the operation times out, or ctx is canceled
func (c *Client) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResult, error) {
	keyLabel, err := normalizeKeyLabel(req.KeyLabel)
	if err != nil {
		return nil, err
	}

	err = validateEncryptionAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	if len(req.Plaintext) == 0 {
		return nil, errors.New("plaintext is required")
	}

	err = ensureWithinPayloadLimit("plaintext", len(req.Plaintext))
	if err != nil {
		return nil, err
	}

	err = ensureWithinPayloadLimit("additional data", len(req.AdditionalData))
	if err != nil {
		return nil, err
	}

	opts, err := c.resolve(req.Timeout, req.Note)
	if err != nil {
		return nil, err
	}

	res, err := c.execute(ctx, clientcore.Request{
		Operation:      protocolv2.OperationEncrypt,
		KeyLabel:       keyLabel,
		Algorithm:      req.Algorithm,
		Timeout:        opts.timeout,
		Note:           opts.note,
		Value:          base64.RawURLEncoding.EncodeToString(req.Plaintext),
		AdditionalData: base64.RawURLEncoding.EncodeToString(req.AdditionalData),
	})
	if err != nil {
		return nil, err
	}

	var resp encryptResponsePayload
	err = json.Unmarshal(res.Payload, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypt response JSON: %w", err)
	}
	if resp.State != res.State {
		return nil, errors.New("encrypt response state mismatch")
	}
	if resp.Operation != protocolv2.OperationEncrypt {
		return nil, fmt.Errorf("unexpected operation in encrypt response: %q", resp.Operation)
	}
	if resp.Algorithm != req.Algorithm {
		return nil, fmt.Errorf("encrypt response algorithm %q does not match requested %q", resp.Algorithm, req.Algorithm)
	}
	if resp.Value == "" || resp.Nonce == "" || resp.Tag == "" {
		return nil, errors.New("encrypt response missing value/nonce/tag")
	}

	ciphertext, err := decodeResponseField("value", resp.Value)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeResponseField("nonce", resp.Nonce)
	if err != nil {
		return nil, err
	}
	tag, err := decodeResponseField("tag", resp.Tag)
	if err != nil {
		return nil, err
	}

	// The browser echoes the additional data it bound to the ciphertext
	// Any difference from what was requested means the message is not the one the caller asked for
	aad := req.AdditionalData
	if resp.AdditionalData != "" {
		aad, err = decodeResponseField("additionalData", resp.AdditionalData)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(aad, req.AdditionalData) {
			return nil, errors.New("encrypt response additional data does not match the request")
		}
	}

	return &EncryptResult{
		KeyLabel:       keyLabel,
		Algorithm:      resp.Algorithm,
		Ciphertext:     ciphertext,
		Nonce:          nonce,
		Tag:            tag,
		AdditionalData: aad,
		State:          res.State,
	}, nil
}

// decodeResponseField decodes a base64url-encoded field from a response produced by the browser
func decodeResponseField(name string, value string) ([]byte, error) {
	res, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s in response: %w", name, err)
	}

	return res, nil
}
