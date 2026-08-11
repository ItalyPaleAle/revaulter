package clientcore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// SigningPubkeyResponse mirrors the server's GET /v2/request/signing-pubkey response
type SigningPubkeyResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	JWK       json.RawMessage `json:"jwk"`

	// Anchor-signed publication proof, empty for keys the user has not published
	PublicationPayload          string `json:"publicationPayload"`
	PublicationSignatureEs384   string `json:"publicationSignatureEs384"`
	PublicationSignatureMldsa87 string `json:"publicationSignatureMldsa87"`
}

// SigningKey is a public signing key advertised by the server, after it has been bound to the pinned anchor
type SigningKey struct {
	// ID is the identifier the server assigned to the key
	ID string
	// KeyLabel is the logical key label the key belongs to
	KeyLabel string
	// Algorithm is the signing algorithm the key is used with
	Algorithm string
	// KeyID is the RFC 7638 JWK thumbprint, which is the same identifier the browser echoes in sign responses
	KeyID string
	// PublicKey is the parsed public key: *ecdsa.PublicKey for ES256, ed25519.PublicKey for Ed25519 and Ed25519ph
	PublicKey crypto.PublicKey
	// JWK is the raw JWK returned by the server
	JWK json.RawMessage
}

// SigningPublicKey retrieves the stored signing public key for the given label and algorithm
// The key is only returned after its anchor-signed publication proof has been verified against the anchor pinned in the trust store, so a compromised server cannot substitute a key of its choosing
// When the trust store is disabled there is no trusted anchor to verify against and the key is returned unverified
func (c *Client) SigningPublicKey(ctx context.Context, keyLabel string, algorithm string) (*SigningKey, error) {
	anchor, err := c.VerifyAnchorTrust(ctx)
	if err != nil {
		return nil, err
	}

	// Create the request
	query := url.Values{}
	query.Set("label", keyLabel)
	query.Set("algorithm", algorithm)
	req, err := c.newRequest(ctx, http.MethodGet, "signing-pubkey?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}

	// Parse the response
	var resp SigningPubkeyResponse
	err = c.doJSON(req, &resp)
	if err != nil {
		return nil, fmt.Errorf("fetch signing pubkey: %w", err)
	}

	// The server looks the key up by the exact label and algorithm, so anything else means the response does not belong to this request
	if resp.Algorithm != algorithm {
		return nil, fmt.Errorf("server returned a signing key for algorithm %q, but %q was requested", resp.Algorithm, algorithm)
	}
	if resp.KeyLabel != keyLabel {
		return nil, fmt.Errorf("server returned a signing key for label %q, but %q was requested", resp.KeyLabel, keyLabel)
	}

	// Parse the JWK and derive its thumbprint
	// The thumbprint is what the publication proof binds, so it must be computed locally from the returned key material rather than read from the response
	key, err := parseSigningPubkeyResponse(&resp)
	if err != nil {
		return nil, err
	}

	// Bind the key to the pinned anchor
	// Without this the server is free to advertise any key it likes
	err = verifySigningKeyPublication(anchor, &resp, key.KeyID, keyLabel, algorithm, c.server)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// parseSigningPubkeyResponse converts the JWK in the response into a public key and computes its RFC 7638 thumbprint
func parseSigningPubkeyResponse(resp *SigningPubkeyResponse) (*SigningKey, error) {
	key := &SigningKey{
		ID:        resp.ID,
		KeyLabel:  resp.KeyLabel,
		Algorithm: resp.Algorithm,
		JWK:       resp.JWK,
	}

	switch resp.Algorithm {
	case protocolv2.SigningAlgES256:
		jwk, err := protocolv2.ParseECP256SigningJWK(resp.JWK)
		if err != nil {
			return nil, fmt.Errorf("parse signing key JWK: %w", err)
		}

		ecdhPub, err := jwk.ToECDHPublicKey()
		if err != nil {
			return nil, fmt.Errorf("invalid signing public key: %w", err)
		}

		key.KeyID, err = jwk.Thumbprint()
		if err != nil {
			return nil, fmt.Errorf("compute signing key thumbprint: %w", err)
		}

		// Convert raw uncompressed point (04 || x || y) to *ecdsa.PublicKey
		raw := ecdhPub.Bytes()
		key.PublicKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(raw[1:33]),
			Y:     new(big.Int).SetBytes(raw[33:65]),
		}

	case protocolv2.SigningAlgEd25519, protocolv2.SigningAlgEd25519ph:
		jwk, err := protocolv2.ParseEd25519SigningJWK(resp.JWK)
		if err != nil {
			return nil, fmt.Errorf("parse signing key JWK: %w", err)
		}

		edPub, err := jwk.ToPublicKey()
		if err != nil {
			return nil, fmt.Errorf("invalid signing public key: %w", err)
		}

		key.KeyID, err = jwk.Thumbprint()
		if err != nil {
			return nil, fmt.Errorf("compute signing key thumbprint: %w", err)
		}

		key.PublicKey = ed25519.PublicKey(edPub)

	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", resp.Algorithm)
	}

	return key, nil
}

// verifySigningKeyPublication checks the anchor-signed publication proof that binds the fetched signing key to the user's pinned anchor
// Verification is skipped only when the trust store is disabled, in which case there is no trusted anchor to verify against
func verifySigningKeyPublication(anchor *PinnedAnchor, resp *SigningPubkeyResponse, keyID string, keyLabel string, algorithm string, server string) error {
	if anchor == nil {
		return nil
	}

	// Auto-stored keys carry no proof: the server registers them as a side effect of the first sign, which is not an explicit user decision and is therefore not something the anchor has vouched for
	if resp.PublicationPayload == "" || resp.PublicationSignatureEs384 == "" || resp.PublicationSignatureMldsa87 == "" {
		return fmt.Errorf(
			"the signing key for label %q (algorithm %s) has no publication proof, so it cannot be verified against the anchor pinned for %s; publish the key from the Revaulter web interface, then try again",
			keyLabel, algorithm, server,
		)
	}

	_, err := protocolv2.VerifySigningKeyPublicResponse(
		resp.PublicationPayload,
		resp.PublicationSignatureEs384,
		resp.PublicationSignatureMldsa87,
		protocolv2.SigningKeyPublicResponseVerifyOptions{
			Es384Pub:        anchor.Es384Pub,
			Mldsa87PubBytes: anchor.Mldsa87PubBytes,
			// Every field the caller has an expectation for is pinned, so a proof captured for a different user, key, or label cannot be replayed here
			ExpectedUserID:    anchor.UserID,
			ExpectedAlgorithm: algorithm,
			ExpectedKeyLabel:  keyLabel,
			ExpectedKeyID:     keyID,
		},
	)
	if err != nil {
		return fmt.Errorf("publication proof for the advertised signing key is not valid: %w", err)
	}

	return nil
}
