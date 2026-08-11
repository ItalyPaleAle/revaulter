package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// defaultResultTimeout is how long the client waits for a response when the request does not set a timeout
const defaultResultTimeout = 15 * time.Minute

// resultTimeoutGrace is added to the request's timeout so the server's expiry fires first and produces a clean "failed" response
const resultTimeoutGrace = 30 * time.Second

// Request is a low-level request for an operation that requires the user's approval in the browser
// The payload fields are base64url-encoded because that is how they travel inside the end-to-end encrypted envelope
type Request struct {
	Operation string
	KeyLabel  string
	Algorithm string
	Timeout   time.Duration
	Note      string

	Value          string
	Nonce          string
	Tag            string
	AdditionalData string

	// OnSubmitted, when set, is invoked with the request's state right after the request has been accepted by the server, and before waiting for the user's approval
	OnSubmitted func(state string)
}

// Response is the result of an operation approved by the user
type Response struct {
	// State is the identifier the server assigned to the request
	State string
	// Payload is the raw JSON payload the browser produced, after the end-to-end encrypted envelope has been decrypted
	Payload []byte
}

// operationRequestBody is the body of the request submitted to the server
type operationRequestBody struct {
	KeyLabel  string `json:"keyLabel,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	Timeout string `json:"timeout,omitempty"`
	Note    string `json:"note,omitempty"`

	// E2EE envelope
	RequestEncAlg         string                     `json:"requestEncAlg"`
	CliEphemeralPublicKey protocolv2.ECP256PublicJWK `json:"cliEphemeralPublicKey"`
	MlkemCiphertext       string                     `json:"mlkemCiphertext"`
	EncryptedPayloadNonce string                     `json:"encryptedPayloadNonce"`
	EncryptedPayload      string                     `json:"encryptedPayload"`
}

// Execute submits an operation to the server, waits for the user to approve it in the browser, and returns the decrypted response payload
func (c *Client) Execute(ctx context.Context, req Request) (*Response, error) {
	kp, err := NewTransportKeyPair()
	if err != nil {
		return nil, err
	}

	state, err := c.CreateRequest(ctx, req, kp)
	if err != nil {
		return nil, fmt.Errorf("failed to start operation: %w", err)
	}

	if req.OnSubmitted != nil {
		req.OnSubmitted(state)
	}

	aad := BuildTransportAAD(state, req.Operation, req.Algorithm)
	payload, err := c.GetResult(ctx, state, kp, aad, req.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}

	return &Response{
		State:   state,
		Payload: payload,
	}, nil
}

// CreateRequest submits a new operation request to the server and returns its state
// The inner payload is encrypted to the user's static public keys, so the server cannot read it
func (c *Client) CreateRequest(ctx context.Context, req Request, kp *TransportKeyPair) (string, error) {
	if kp == nil {
		return "", errors.New("missing transport key pair")
	}

	// Fetch the user's static public keys (ECDH + ML-KEM) alongside the hybrid anchor bundle so the client can pin the anchor on first contact and refuse any subsequent pubkey substitution
	pubkeys, err := c.fetchAndVerifyUserPubkeys(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user public keys: %w", err)
	}

	// Build the inner payload (sensitive fields)
	innerPayload := protocolv2.RequestPayloadInner{
		Value:                   req.Value,
		Nonce:                   req.Nonce,
		Tag:                     req.Tag,
		AdditionalData:          req.AdditionalData,
		ClientTransportEcdhKey:  kp.EcdhPublic,
		ClientTransportMlkemKey: kp.MlkemPublic,
	}

	// Build AAD from plaintext metadata
	aad := BuildRequestEncAAD(req.Algorithm, req.KeyLabel, req.Operation)

	// Encrypt the inner payload with hybrid ECDH + ML-KEM
	cliEphPub, mlkemCiphertext, nonce, ciphertext, err := EncryptRequestPayload(pubkeys.Ecdh, pubkeys.Mlkem, innerPayload, aad)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt request payload: %w", err)
	}

	// Build the outer request body
	outerBody := operationRequestBody{
		KeyLabel:              req.KeyLabel,
		Algorithm:             req.Algorithm,
		Timeout:               FormatTimeout(req.Timeout),
		Note:                  req.Note,
		RequestEncAlg:         protocolv2.TransportAlg,
		CliEphemeralPublicKey: cliEphPub,
		MlkemCiphertext:       mlkemCiphertext,
		EncryptedPayloadNonce: nonce,
		EncryptedPayload:      ciphertext,
	}

	body, err := json.Marshal(outerBody)
	if err != nil {
		return "", err
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, req.Operation, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	var res protocolv2.RequestResultResponse
	err = c.doJSON(httpReq, &res)
	if err != nil {
		return "", err
	}
	if !res.Pending || res.State == "" {
		return "", errors.New("invalid create response")
	}

	return res.State, nil
}

// GetResult polls the server until the operation completes and returns the decrypted response payload
func (c *Client) GetResult(ctx context.Context, state string, kp *TransportKeyPair, aad []byte, timeout time.Duration) ([]byte, error) {
	if kp == nil {
		return nil, errors.New("missing transport key pair")
	}

	// Apply a local deadline so the client can't poll indefinitely if the server hangs, drops the state, or keeps returning pending beyond the negotiated timeout
	// Use the caller-supplied timeout plus a small grace window so the server's expiry fires first and produces a clean "failed" response; fall back to a sensible default when unset
	localTimeout := defaultResultTimeout
	if timeout > 0 {
		localTimeout = timeout + resultTimeoutGrace
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, localTimeout)
	defer cancel()

	// The server long-polls and may return {pending:true} when its own subscription window elapses, when the broker is saturated, or when the subscriber slot is temporarily unavailable
	// Treat those as "keep waiting" and re-issue the request until the context is canceled (or its deadline is reached)
	// A short backoff avoids tight-spinning if the server ever returns pending immediately
	const minBackoff = 250 * time.Millisecond
	const maxBackoff = 2 * time.Second
	backoff := minBackoff

	for {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}

		req, err := c.newRequest(ctx, http.MethodGet, "result/"+state, nil)
		if err != nil {
			return nil, err
		}
		var res protocolv2.RequestResultResponse
		err = c.doJSON(req, &res)
		if err != nil {
			return nil, err
		}
		if res.State != state {
			return nil, errors.New("response state mismatch")
		}
		if res.Pending {
			c.log.Debug("Server long-poll returned pending, reconnecting",
				slog.String("state", state),
				slog.Duration("backoff", backoff),
			)
			// Wait briefly before reconnecting
			// The typical server long-poll already covered the bulk of the wait time, so this backoff only kicks in if the server is returning pending quickly
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		if res.Failed {
			return nil, errors.New("operation is canceled, denied, or failed")
		}
		if !res.Done || res.ResponseEnvelope == nil {
			return nil, errors.New("missing encrypted response envelope")
		}
		return DecryptResponseEnvelope(state, kp, res.ResponseEnvelope, aad)
	}
}

// FormatTimeout formats a timeout in the format expected by the server, returning an empty string when the timeout is not set
func FormatTimeout(d time.Duration) string {
	if d <= 0 {
		return ""
	}

	return d.String()
}
