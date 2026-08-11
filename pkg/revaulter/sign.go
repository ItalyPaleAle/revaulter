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

// signatureSize is the size of every signature Revaulter produces: 64 bytes for both ECDSA P-256 (r||s) and Ed25519
const signatureSize = 64

// SignRequest is the request for the [Client.Sign] operation
type SignRequest struct {
	// Logical label of the key used to sign the message (required)
	KeyLabel string
	// Signing algorithm: AlgorithmES256, AlgorithmEd25519, or AlgorithmEd25519ph (required)
	Algorithm string
	// Message to sign
	// It is hashed as required by the algorithm before being sent to the browser, so only the digest leaves the machine for ES256 and Ed25519ph, and the message itself can be of any size
	// Ed25519 signs the message itself, so it is limited to MaxPayloadSize bytes
	// Exactly one of Message or Digest is required
	Message []byte
	// Pre-computed digest of the message to sign: 32 bytes (SHA-256) for ES256, or 64 bytes (SHA-512) for Ed25519ph
	// Ed25519 signs the message itself, so it does not accept a digest
	Digest []byte

	// Optional timeout for the operation, which overrides the client's default
	Timeout time.Duration
	// Optional note displayed to the user alongside the request, which overrides the client's default
	Note string
}

// SignResult is the result of the [Client.Sign] operation
type SignResult struct {
	// Logical label of the key the message was signed with
	KeyLabel string
	// Algorithm the message was signed with
	Algorithm string
	// Raw signature: 64 bytes, in the IEEE P1363 r||s form for ES256
	Signature []byte
	// SigningKeyID is the RFC 7638 thumbprint of the key the browser signed with
	// Callers that pinned a specific key, for example one obtained from Client.SigningPublicKey, should compare it against SigningKey.KeyID
	SigningKeyID string
	// Identifier the server assigned to the request that produced this result
	State string
}

// signResponsePayload is the JSON shape produced by the browser after signing
// Signature carries the base64url-encoded raw signature bytes
type signResponsePayload struct {
	State     string `json:"state"`
	Operation string `json:"operation"`
	Algorithm string `json:"algorithm"`
	KeyLabel  string `json:"keyLabel"`
	Signature string `json:"signature"`

	// SigningKeyID is the RFC 7638 thumbprint of the key the browser actually signed with
	SigningKeyID string `json:"signingKeyId"`
}

// Sign signs a message with a key held by the user, after they approve the request in their browser
// The call blocks until the user approves or denies the request, the operation times out, or ctx is canceled
func (c *Client) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	keyLabel, err := normalizeKeyLabel(req.KeyLabel)
	if err != nil {
		return nil, err
	}

	algorithm, err := normalizeSigningAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	value, err := resolveSigningInput(algorithm, req.Message, req.Digest)
	if err != nil {
		return nil, err
	}

	// Only the value that actually travels to the browser counts against the limit
	// ES256 and Ed25519ph sign a digest, so the message they are computed from can be of any size
	err = ensureWithinPayloadLimit("signing input", len(value))
	if err != nil {
		return nil, err
	}

	opts, err := c.resolve(req.Timeout, req.Note)
	if err != nil {
		return nil, err
	}

	res, err := c.execute(ctx, clientcore.Request{
		Operation: protocolv2.OperationSign,
		KeyLabel:  keyLabel,
		Algorithm: algorithm,
		Timeout:   opts.timeout,
		Note:      opts.note,
		Value:     base64.RawURLEncoding.EncodeToString(value),
	})
	if err != nil {
		return nil, err
	}

	var resp signResponsePayload
	err = json.Unmarshal(res.Payload, &resp)
	if err != nil {
		return nil, fmt.Errorf("invalid sign response JSON: %w", err)
	}
	if resp.State != res.State {
		return nil, errors.New("sign response state mismatch")
	}
	if resp.Operation != protocolv2.OperationSign {
		return nil, fmt.Errorf("unexpected operation in sign response: %q", resp.Operation)
	}
	if resp.Algorithm != algorithm {
		return nil, fmt.Errorf("unexpected algorithm in sign response: %q", resp.Algorithm)
	}
	if resp.KeyLabel != keyLabel {
		return nil, fmt.Errorf("sign response keyLabel %q does not match requested %q", resp.KeyLabel, keyLabel)
	}
	if resp.Signature == "" {
		return nil, errors.New("sign response missing signature")
	}

	signature, err := decodeResponseField("signature", resp.Signature)
	if err != nil {
		return nil, err
	}
	if len(signature) != signatureSize {
		return nil, fmt.Errorf("unexpected signature length: got %d bytes, want %d", len(signature), signatureSize)
	}

	return &SignResult{
		KeyLabel:     keyLabel,
		Algorithm:    algorithm,
		Signature:    signature,
		SigningKeyID: resp.SigningKeyID,
		State:        res.State,
	}, nil
}
