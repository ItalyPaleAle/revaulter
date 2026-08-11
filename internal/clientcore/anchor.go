package clientcore

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/italypaleale/revaulter/internal/protocolv2"
)

// PubkeyResponse mirrors the server's GET /v2/request/pubkey response
type PubkeyResponse struct {
	UserID   string          `json:"userId"`
	EcdhP256 json.RawMessage `json:"ecdhP256"`
	Mlkem768 string          `json:"mlkem768"`

	AnchorEs384PublicKey         string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey       string `json:"anchorMldsa87PublicKey"`
	PubkeyBundleSignatureEs384   string `json:"pubkeyBundleSignatureEs384"`
	PubkeyBundleSignatureMldsa87 string `json:"pubkeyBundleSignatureMldsa87"`

	// PubkeyBundleVersion selects the canonical payload the signatures cover
	// Servers that predate versioning omit it, which means v1
	PubkeyBundleVersion int64 `json:"pubkeyBundleVersion"`
}

// PinnedAnchor carries the anchor identity that was confirmed against the trust store
// Callers use it to verify anchor-signed material, so the keys here must always be the ones that survived the pin check
type PinnedAnchor struct {
	UserID          string
	Es384Pub        *ecdsa.PublicKey
	Mldsa87PubBytes []byte
}

// FetchPubkeyBundle retrieves the user's static public keys and the hybrid anchor bundle from the server
// The response is not verified: use VerifyAndPinAnchor for that
func (c *Client) FetchPubkeyBundle(ctx context.Context) (*PubkeyResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "pubkey", nil)
	if err != nil {
		return nil, err
	}

	resp := &PubkeyResponse{}
	err = c.doJSON(req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// TrustStorePath returns the path of the trust store used by the client, resolving the default when not configured
func (c *Client) TrustStorePath() (string, error) {
	return ResolveTrustStorePath(c.trustStorePath)
}

// verifyAndPinResponse checks the anchor bundle in resp against the trust store, pinning it on first contact
// It returns nil when anchor pinning is disabled
func (c *Client) verifyAndPinResponse(resp *PubkeyResponse) (*PinnedAnchor, error) {
	if c.noTrustStore {
		c.log.Warn("Skipping anchor pinning and hybrid bundle verification because the trust store is disabled")
		return nil, nil
	}

	path, err := c.TrustStorePath()
	if err != nil {
		return nil, err
	}

	ts, err := LoadTrustStore(path)
	if err != nil {
		return nil, err
	}

	pinned, err := VerifyAndPinAnchor(c.server, resp, ts, c.confirmAnchor)
	if err != nil {
		return nil, fmt.Errorf("anchor trust check failed: %w", err)
	}

	if pinned {
		err = SaveTrustStore(path, ts)
		if err != nil {
			return nil, fmt.Errorf("save trust store: %w", err)
		}
		c.log.Info("Pinned anchor on first contact", slog.String("trust_store", path))
	}

	// Re-parse from the wire values, which VerifyAndPinAnchor has just confirmed byte-for-byte against the pinned entry
	es384Pub, mldsa87PubBytes, err := ParseAnchorPubkeysFromWire(resp.AnchorEs384PublicKey, resp.AnchorMldsa87PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid anchor public key: %w", err)
	}

	return &PinnedAnchor{
		UserID:          resp.UserID,
		Es384Pub:        es384Pub,
		Mldsa87PubBytes: mldsa87PubBytes,
	}, nil
}

// VerifyAnchorTrust fetches the server's anchor bundle and checks it against the trust store, pinning it on first contact
// It returns nil when anchor pinning is disabled
func (c *Client) VerifyAnchorTrust(ctx context.Context) (*PinnedAnchor, error) {
	if c.noTrustStore {
		c.log.Warn("Skipping anchor pinning, hybrid bundle verification, and signing key publication proof checks because the trust store is disabled")
		return nil, nil
	}

	resp, err := c.FetchPubkeyBundle(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch server pubkey bundle: %w", err)
	}

	return c.verifyAndPinResponse(resp)
}

// userPublicKeys carries the user's static request-encryption public keys
type userPublicKeys struct {
	UserID string
	Ecdh   *ecdh.PublicKey
	Mlkem  *mlkem.EncapsulationKey768
}

// fetchAndVerifyUserPubkeys fetches the user's static public keys (ECDH + ML-KEM) alongside the hybrid anchor bundle, so the client can pin the anchor on first contact and refuse any subsequent pubkey substitution
func (c *Client) fetchAndVerifyUserPubkeys(ctx context.Context) (*userPublicKeys, error) {
	resp, err := c.FetchPubkeyBundle(ctx)
	if err != nil {
		return nil, err
	}

	var ecdhJWK protocolv2.ECP256PublicJWK
	err = json.Unmarshal(resp.EcdhP256, &ecdhJWK)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDH public key: %w", err)
	}
	ecdhPub, err := ecdhJWK.ToECDHPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid ECDH public key: %w", err)
	}

	mlkemBytes, err := base64.RawURLEncoding.DecodeString(resp.Mlkem768)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM public key encoding: %w", err)
	}
	mlkemPub, err := mlkem.NewEncapsulationKey768(mlkemBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ML-KEM public key: %w", err)
	}

	_, err = c.verifyAndPinResponse(resp)
	if err != nil {
		return nil, err
	}

	return &userPublicKeys{
		UserID: resp.UserID,
		Ecdh:   ecdhPub,
		Mlkem:  mlkemPub,
	}, nil
}

// VerifyAndPinAnchor validates the hybrid anchor bundle in resp, verifies both signatures, then checks or pins the anchor in ts
// Returns pinned=true when the anchor was newly pinned (the caller must save the trust store in that case)
func VerifyAndPinAnchor(server string, resp *PubkeyResponse, ts *TrustStore, confirm ConfirmAnchorFunc) (pinned bool, err error) {
	if len(resp.AnchorEs384PublicKey) == 0 || resp.AnchorMldsa87PublicKey == "" ||
		resp.PubkeyBundleSignatureEs384 == "" || resp.PubkeyBundleSignatureMldsa87 == "" {
		return false, errors.New("server did not return a hybrid anchor bundle; refusing to proceed (use --no-trust-store to override)")
	}

	if resp.UserID == "" {
		return false, errors.New("server did not return userId; refusing to proceed (use --no-trust-store to override)")
	}

	es384Pub, mldsa87PubBytes, err := ParseAnchorPubkeysFromWire(resp.AnchorEs384PublicKey, resp.AnchorMldsa87PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid anchor public key: %w", err)
	}

	// Verify both halves of the hybrid bundle signature against the server-provided anchor pubkeys
	// The subsequent pin check catches anchor rotation
	// This catches a server that serves a corrupt or mismatched bundle
	es384JWK, err := protocolv2.ParseECP384PublicJWKCanonicalBody(resp.AnchorEs384PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid anchorEs384PublicKey: %w", err)
	}

	sigEs, sigMl, err := DecodeHybridSignatures(resp.PubkeyBundleSignatureEs384, resp.PubkeyBundleSignatureMldsa87)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey bundle signature: %w", err)
	}

	// The bundle is signed once at signup and never re-signed
	// The advertised pubkeyBundleVersion (absent on servers that predate versioning, i.e. v1) selects the canonical payload to reconstruct
	version := resp.PubkeyBundleVersion
	if version == 0 {
		version = protocolv2.PubkeyBundleVersion1
	}
	switch version {
	case protocolv2.PubkeyBundleVersion1:
		// Legacy payload: always bound to WrappedKeyEpoch = 1, so it is reconstructed with that constant rather than the server-reported epoch
		// Servers used to echo the user's live epoch in the response, which advances on password changes and would make verification fail for a signature that is still valid
		bundlePayload := &protocolv2.PubkeyBundlePayload{
			UserID:                 resp.UserID,
			RequestEncEcdhPubkey:   string(resp.EcdhP256),
			RequestEncMlkemPubkey:  resp.Mlkem768,
			AnchorEs384Crv:         es384JWK.Crv,
			AnchorEs384Kty:         es384JWK.Kty,
			AnchorEs384X:           es384JWK.X,
			AnchorEs384Y:           es384JWK.Y,
			AnchorMldsa87PublicKey: resp.AnchorMldsa87PublicKey,
			WrappedKeyEpoch:        protocolv2.PubkeyBundleWrappedKeyEpoch,
		}
		err = protocolv2.VerifyHybridBundle(es384Pub, mldsa87PubBytes, bundlePayload, sigEs, sigMl)
	case protocolv2.PubkeyBundleVersion2:
		bundlePayload := &protocolv2.PubkeyBundlePayloadV2{
			UserID:                 resp.UserID,
			RequestEncEcdhPubkey:   string(resp.EcdhP256),
			RequestEncMlkemPubkey:  resp.Mlkem768,
			AnchorEs384Crv:         es384JWK.Crv,
			AnchorEs384Kty:         es384JWK.Kty,
			AnchorEs384X:           es384JWK.X,
			AnchorEs384Y:           es384JWK.Y,
			AnchorMldsa87PublicKey: resp.AnchorMldsa87PublicKey,
			V:                      protocolv2.PubkeyBundleVersion2,
		}
		err = protocolv2.VerifyHybridBundleV2(es384Pub, mldsa87PubBytes, bundlePayload, sigEs, sigMl)
	default:
		return false, fmt.Errorf("server advertised unsupported pubkey bundle version %d - please upgrade revaulter", version)
	}
	if err != nil {
		return false, fmt.Errorf("pubkey bundle signature verification failed: %w", err)
	}

	return ts.CheckOrPinAnchor(
		server, resp.UserID,
		es384Pub, resp.AnchorEs384PublicKey,
		resp.AnchorMldsa87PublicKey, mldsa87PubBytes,
		confirm,
	)
}

// ParseAnchorPubkeysFromWire decodes the client-facing wire form of the hybrid anchor
func ParseAnchorPubkeysFromWire(es384JWK string, mldsa87PubB64 string) (*ecdsa.PublicKey, []byte, error) {
	jwk, err := protocolv2.ParseECP384PublicJWKCanonicalBody(es384JWK)
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 JWK: %w", err)
	}

	ecdsaPub, err := jwk.ToECDSAPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 pubkey: %w", err)
	}

	mldsa87PubBytes, err := base64.RawURLEncoding.DecodeString(mldsa87PubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87 pubkey base64: %w", err)
	}

	if len(mldsa87PubBytes) != protocolv2.MLDSA87PublicKeySize {
		return nil, nil, fmt.Errorf("ML-DSA-87 pubkey: expected %d bytes, got %d", protocolv2.MLDSA87PublicKeySize, len(mldsa87PubBytes))
	}

	return ecdsaPub, mldsa87PubBytes, nil
}

// DecodeHybridSignatures decodes base64url-encoded ES384 + ML-DSA-87 signatures and validates their sizes
func DecodeHybridSignatures(es384B64, mldsa87B64 string) (sigEs, sigMl []byte, err error) {
	sigEs, err = protocolv2.DecodeBase64Signature(es384B64, protocolv2.ES384SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ES384 sig: %w", err)
	}
	sigMl, err = protocolv2.DecodeBase64Signature(mldsa87B64, protocolv2.MLDSA87SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87 sig: %w", err)
	}
	return sigEs, sigMl, nil
}
