package revaulter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/italypaleale/revaulter/internal/clientcore"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// DecryptRequest is the request for the [Client.Decrypt] operation
type DecryptRequest struct {
	// Logical label of the key the message was encrypted with (required)
	KeyLabel string
	// Algorithm the message was encrypted with, such as AlgorithmA256GCM (required)
	Algorithm string
	// Encrypted message (required)
	// Messages are limited to MaxPayloadSize bytes
	Ciphertext []byte
	// Nonce (or IV) the message was encrypted with
	Nonce []byte
	// Authentication tag
	Tag []byte
	// Additional authenticated data bound to the ciphertext, if any
	AdditionalData []byte

	// Optional timeout for the operation, which overrides the client's default
	Timeout time.Duration
	// Optional note displayed to the user alongside the request, which overrides the client's default
	Note string
}

// DecryptResult is the result of the [Client.Decrypt] operation
type DecryptResult struct {
	// Logical label of the key the message was encrypted with
	KeyLabel string
	// Algorithm the message was encrypted with
	Algorithm string
	// Decrypted message
	Plaintext []byte
	// Identifier the server assigned to the request that produced this result
	State string
}

// decryptResponsePayload is the JSON shape produced by the browser after decrypting
// Value carries the base64url-encoded plaintext bytes
type decryptResponsePayload struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Decrypt decrypts a message with a key held by the user, after they approve the request in their browser
// The call blocks until the user approves or denies the request, the operation times out, or ctx is canceled
func (c *Client) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResult, error) {
	keyLabel, err := normalizeKeyLabel(req.KeyLabel)
	if err != nil {
		return nil, err
	}

	err = validateEncryptionAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	if len(req.Ciphertext) == 0 {
		return nil, errors.New("ciphertext is required")
	}

	err = ensureWithinPayloadLimit("ciphertext", len(req.Ciphertext))
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
		Operation:      protocolv2.OperationDecrypt,
		KeyLabel:       keyLabel,
		Algorithm:      req.Algorithm,
		Timeout:        opts.timeout,
		Note:           opts.note,
		Value:          base64.RawURLEncoding.EncodeToString(req.Ciphertext),
		Nonce:          base64.RawURLEncoding.EncodeToString(req.Nonce),
		Tag:            base64.RawURLEncoding.EncodeToString(req.Tag),
		AdditionalData: base64.RawURLEncoding.EncodeToString(req.AdditionalData),
	})
	if err != nil {
		return nil, err
	}

	var resp decryptResponsePayload
	err = json.Unmarshal(res.Payload, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid decrypt response JSON: %w", err)
	}
	if resp.State != res.State {
		return nil, errors.New("decrypt response state mismatch")
	}
	if resp.Operation != protocolv2.OperationDecrypt {
		return nil, fmt.Errorf("unexpected operation in decrypt response: %q", resp.Operation)
	}
	if resp.Algorithm != req.Algorithm {
		return nil, fmt.Errorf("decrypt response algorithm %q does not match requested %q", resp.Algorithm, req.Algorithm)
	}
	if resp.Value == "" {
		return nil, errors.New("decrypt response missing value")
	}

	plaintext, err := decodeResponseField("value", resp.Value)
	if err != nil {
		return nil, err
	}

	return &DecryptResult{
		KeyLabel:  keyLabel,
		Algorithm: resp.Algorithm,
		Plaintext: plaintext,
		State:     res.State,
	}, nil
}
