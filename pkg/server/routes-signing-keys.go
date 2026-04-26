package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

// signingKeyPublicationCreatedAtSkew bounds how far a signed publication payload's `createdAt` may drift from server now
// The skew check runs at write time only, so once a row is stored as proven, later publish/unpublish toggles do not re-evaluate this window
const signingKeyPublicationCreatedAtSkew = 2 * time.Minute

type v2SigningKeyCreateRequest struct {
	Algorithm                   string          `json:"algorithm"`
	KeyLabel                    string          `json:"keyLabel"`
	JWK                         json.RawMessage `json:"jwk"`
	PEM                         string          `json:"pem"`
	Published                   bool            `json:"published"`
	PublicationPayload          string          `json:"publicationPayload,omitempty"`
	PublicationSignatureEs384   string          `json:"publicationSignatureEs384,omitempty"`
	PublicationSignatureMldsa87 string          `json:"publicationSignatureMldsa87,omitempty"`
}

// HasProof reports whether the request carries all three publication-proof fields
func (req *v2SigningKeyCreateRequest) HasProof() bool {
	return req.PublicationPayload != "" || req.PublicationSignatureEs384 != "" || req.PublicationSignatureMldsa87 != ""
}

func (req *v2SigningKeyCreateRequest) Validate() (kid string, canonicalJWK []byte, err error) {
	if req.Algorithm == "" {
		return "", nil, errors.New("missing algorithm")
	}
	if !protocolv2.IsSupportedSigningAlgorithm(req.Algorithm) {
		return "", nil, fmt.Errorf("unsupported signing algorithm %q", req.Algorithm)
	}
	if req.KeyLabel == "" {
		return "", nil, errors.New("missing keyLabel")
	}

	// Normalize to the canonical (lowercase, restricted-charset) form so the row matches whatever the encrypt/decrypt/sign flow registered for the same label
	canonicalKeyLabel, ok := protocolv2.NormalizeAndValidateKeyLabel(req.KeyLabel)
	if !ok {
		return "", nil, fmt.Errorf("keyLabel must be 1-%d bytes and contain only [A-Za-z0-9_.+-]", protocolv2.MaxKeyLabelLength)
	}
	req.KeyLabel = canonicalKeyLabel

	kid, canonicalJWK, err = validateSigningJWKAndPEM(req.JWK, req.PEM)
	if err != nil {
		return "", nil, err
	}

	return kid, canonicalJWK, nil
}

type v2SigningKeyItemResponse struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	KeyLabel  string    `json:"keyLabel"`
	Published bool      `json:"published"`
	HasProof  bool      `json:"hasProof"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func newSigningKeyItemResponse(rec *db.PublishedSigningKey) v2SigningKeyItemResponse {
	return v2SigningKeyItemResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		Published: rec.Published,
		HasProof:  rec.HasPublicationProof(),
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	}
}

type v2SigningKeySetPublishedRequest struct {
	Published                   bool   `json:"published"`
	PublicationPayload          string `json:"publicationPayload,omitempty"`
	PublicationSignatureEs384   string `json:"publicationSignatureEs384,omitempty"`
	PublicationSignatureMldsa87 string `json:"publicationSignatureMldsa87,omitempty"`
}

func (req *v2SigningKeySetPublishedRequest) HasProof() bool {
	return req.PublicationPayload != "" || req.PublicationSignatureEs384 != "" || req.PublicationSignatureMldsa87 != ""
}

type v2SigningKeyDeleteResponse struct {
	Deleted bool `json:"deleted"`
}

type v2SigningKeyDetailResponse struct {
	ID                          string          `json:"id"`
	Algorithm                   string          `json:"algorithm"`
	KeyLabel                    string          `json:"keyLabel"`
	Published                   bool            `json:"published"`
	HasProof                    bool            `json:"hasProof"`
	CreatedAt                   time.Time       `json:"createdAt"`
	UpdatedAt                   time.Time       `json:"updatedAt"`
	JWK                         json.RawMessage `json:"jwk"`
	PEM                         string          `json:"pem"`
	PublicationPayload          string          `json:"publicationPayload,omitempty"`
	PublicationSignatureEs384   string          `json:"publicationSignatureEs384,omitempty"`
	PublicationSignatureMldsa87 string          `json:"publicationSignatureMldsa87,omitempty"`
}

type v2SigningKeyPublicResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	CreatedAt time.Time       `json:"createdAt"`
	JWK       json.RawMessage `json:"jwk"`

	// Anchor-signed publication proof and the user's anchor public keys
	// External clients (and the Revaulter CLI) verify the binding by checking that both signatures cover CanonicalSigningKeyPublicationMessage(payload) under these pubkeys
	PublicationPayload          string `json:"publicationPayload"`
	PublicationSignatureEs384   string `json:"publicationSignatureEs384"`
	PublicationSignatureMldsa87 string `json:"publicationSignatureMldsa87"`
	AnchorEs384PublicKey        string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey      string `json:"anchorMldsa87PublicKey"`
}

// RouteV2APISigningKeyList lists the current user's signing keys
// Only metadata is returned; JWK and PEM are omitted to keep the list lean
func (s *Server) RouteV2APISigningKeyList(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	sks := s.db.SigningKeyStore()
	items, err := sks.ListForUser(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	if items == nil {
		items = []db.PublishedSigningKeyListItem{}
	}

	c.JSON(http.StatusOK, items)
}

// RouteV2APISigningKeyCreate stores a new signing key for the authenticated user
// The client submits JWK and PEM — the server validates them and checks that the JWK thumbprint matches the PEM public point
// A publication proof is required when Published=true and optional otherwise; if a proof is present it is verified against the request material before the row is written
// If a row already exists for `(user, algorithm, keyLabel)` the request is rejected with 409
func (s *Server) RouteV2APISigningKeyCreate(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse and validate the body
	var req v2SigningKeyCreateRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	kid, canonicalJWK, err := req.Validate()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, err.Error()))
		return
	}

	// Publishing requires a proof; storing as unpublished may include one to lock the slot for later promotion without re-signing
	if req.Published && !req.HasProof() {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "publication proof is required when published is true"))
		return
	}

	// Needs a transaction
	rec, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.PublishedSigningKey, error) {
		// If a proof was supplied, verify it against the authenticated user before any database write
		// Verification covers signature, payload version, time, epoch, and field bindings
		if req.HasProof() {
			rErr := s.verifySigningKeyPublicationProof(ctx, tx.AuthStore(), userID, req.Algorithm, req.KeyLabel, kid, req.PublicationPayload, req.PublicationSignatureEs384, req.PublicationSignatureMldsa87)
			if rErr != nil {
				return nil, NewResponseErrorf(http.StatusBadRequest, "publication proof rejected: %v", rErr)
			}
		}

		vRec, rErr := tx.SigningKeyStore().Create(ctx, db.InsertSigningKeyInput{
			ID:                          kid,
			UserID:                      userID,
			Algorithm:                   req.Algorithm,
			KeyLabel:                    req.KeyLabel,
			JWK:                         string(canonicalJWK),
			PEM:                         req.PEM,
			Published:                   req.Published,
			PublicationPayload:          req.PublicationPayload,
			PublicationSignatureEs384:   req.PublicationSignatureEs384,
			PublicationSignatureMldsa87: req.PublicationSignatureMldsa87,
		})
		if errors.Is(rErr, db.ErrSigningKeyAlreadyExists) {
			// Conflict on (user, algorithm, keyLabel)
			return nil, NewResponseError(http.StatusConflict, rErr.Error())
		} else if rErr != nil {
			return nil, rErr
		}

		return vRec, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusCreated, newSigningKeyItemResponse(rec))
}

// RouteV2APISigningKeyUpdate flips the published flag on an existing signing key owned by the session user
// When published=true is requested:
//   - if the row already has a stored proof, the flag is flipped without requiring a fresh proof (the stored proof was verified at insert time and locks the slot)
//   - if the row has no stored proof, a fresh proof is required in the request and verified against the row's material before publishing
//
// Returns a 404 when the id doesn't match a row belonging to the authenticated user
func (s *Server) RouteV2APISigningKeyUpdate(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the key ID from the URL
	id := c.Param("id")
	if id == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing id"))
		return
	}

	// Parse the request body
	var req v2SigningKeySetPublishedRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	// Run verification + update inside a single transaction
	rec, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.PublishedSigningKey, error) {
		sks := tx.SigningKeyStore()

		existing, rErr := sks.GetForUser(ctx, userID, id)
		if rErr != nil {
			return nil, rErr
		}
		if existing == nil {
			return nil, NewResponseError(http.StatusNotFound, "not found")
		}

		// Decide whether a proof needs to be applied
		// If the request carries a proof it is always verified, regardless of req.Published
		if req.HasProof() {
			rErr = s.verifySigningKeyPublicationProof(ctx, tx.AuthStore(), userID, existing.Algorithm, existing.KeyLabel, existing.ID, req.PublicationPayload, req.PublicationSignatureEs384, req.PublicationSignatureMldsa87)
			if rErr != nil {
				return nil, NewResponseErrorf(http.StatusBadRequest, "publication proof rejected: %v", rErr)
			}

			_, rErr = sks.StorePublicationProof(ctx, userID, id, req.PublicationPayload, req.PublicationSignatureEs384, req.PublicationSignatureMldsa87)
			if rErr != nil {
				return nil, rErr
			}
		} else if req.Published && !existing.HasPublicationProof() {
			// Publishing without a stored proof requires the request to provide one
			return nil, NewResponseError(http.StatusBadRequest, "publication proof is required to publish this key")
		}

		updated, rErr := sks.SetPublished(ctx, userID, id, req.Published)
		if rErr != nil {
			return nil, rErr
		}

		return updated, nil
	})
	if errors.Is(err, db.ErrSigningKeyNotFound) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, newSigningKeyItemResponse(rec))
}

// RouteV2APISigningKeyGet returns a signing key owned by the session user, including the stored JWK, PEM, and publication proof (if any)
// Returns 404 when the id doesn't match a row belonging to the authenticated user, so a guessed id can't probe another user's keys
func (s *Server) RouteV2APISigningKeyGet(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the key ID from the URL
	id := c.Param("id")
	if id == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing id"))
		return
	}

	// Query the database
	sks := s.db.SigningKeyStore()
	rec, err := sks.GetForUser(c.Request.Context(), userID, id)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		// GetForUser returns nil if the key exists but doesn't belong to the current user
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}

	// Respond
	c.JSON(http.StatusOK, v2SigningKeyDetailResponse{
		ID:                          rec.ID,
		Algorithm:                   rec.Algorithm,
		KeyLabel:                    rec.KeyLabel,
		Published:                   rec.Published,
		HasProof:                    rec.HasPublicationProof(),
		CreatedAt:                   rec.CreatedAt,
		UpdatedAt:                   rec.UpdatedAt,
		JWK:                         json.RawMessage(rec.JWK),
		PEM:                         rec.PEM,
		PublicationPayload:          rec.PublicationPayload,
		PublicationSignatureEs384:   rec.PublicationSignatureEs384,
		PublicationSignatureMldsa87: rec.PublicationSignatureMldsa87,
	})
}

// RouteV2APISigningKeyDelete deletes a signing key row owned by the session user
// Returns a 404 when the id doesn't match a row belonging to the authenticated user
func (s *Server) RouteV2APISigningKeyDelete(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the key ID from the URL
	id := c.Param("id")
	if id == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing id"))
		return
	}

	// Delete from the database
	sks := s.db.SigningKeyStore()
	ok, err := sks.Delete(c.Request.Context(), userID, id)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if !ok {
		// Key doesn't exist or doesn't belong to the current user
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}

	// Respond
	c.JSON(http.StatusOK, v2SigningKeyDeleteResponse{
		Deleted: true,
	})
}

// RouteV2SigningKeyPublic serves a published signing key in the format requested by the path extension:
// - .jwk and .json return the stored JWK plus the anchor-signed publication proof and the user's anchor public keys
// - .pem and .pub return the PEM
// The endpoint is unauthenticated and rate-limited; unknown IDs and formats return 404
// A row only surfaces here when published=true AND a publication proof is stored, so unproven candidates and auto-stored rows stay hidden
func (s *Server) RouteV2SigningKeyPublic(c *gin.Context) {
	// Get the key ID and requested format (PEM or JWK) by looking at the last path of the URL
	filename := c.Param("filename")
	dot := strings.LastIndexByte(filename, '.')
	if dot <= 0 || dot == len(filename)-1 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}
	id := filename[:dot]
	ext := filename[dot+1:]

	var wantPEM bool
	switch ext {
	case "jwk", "json":
		wantPEM = false
	case "pem", "pub":
		wantPEM = true
	default:
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}

	// Override the cache-control as this route is cacheable
	c.Header("Cache-Control", "public, max-age=600")

	// If we want a PEM, we can choose a shorter path
	if wantPEM {
		rec, err := s.db.SigningKeyStore().GetPublishedByID(c.Request.Context(), id)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if rec == nil {
			// Either one of: key doesn't exist, is not published, or has no stored publication proof
			AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
			return
		}
		c.Header("Content-Type", "application/x-pem-file")
		c.String(http.StatusOK, rec.PEM)
		return
	}

	// We need to use a transaction to read the the key and the attestation in a consistent way
	type publicData struct {
		rec   *db.PublishedSigningKey
		owner *db.User
	}
	data, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (publicData, error) {
		rec, rErr := tx.SigningKeyStore().GetPublishedByID(ctx, id)
		if rErr != nil {
			return publicData{}, rErr
		}
		if rec == nil {
			// Either one of: key doesn't exist, is not published, or has no stored publication proof
			return publicData{}, NewResponseError(http.StatusNotFound, "not found")
		}

		owner, rErr := tx.AuthStore().GetUserByID(ctx, rec.UserID)
		if rErr != nil {
			return publicData{}, rErr
		}
		if owner == nil {
			// Should never happen because the row has an ON DELETE CASCADE
			return publicData{}, NewResponseError(http.StatusNotFound, "not found")
		}

		return publicData{
			rec:   rec,
			owner: owner,
		}, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond with JWK + proof + anchor pubkeys
	c.JSON(http.StatusOK, v2SigningKeyPublicResponse{
		ID:                          data.rec.ID,
		Algorithm:                   data.rec.Algorithm,
		KeyLabel:                    data.rec.KeyLabel,
		CreatedAt:                   data.rec.CreatedAt,
		JWK:                         json.RawMessage(data.rec.JWK),
		PublicationPayload:          data.rec.PublicationPayload,
		PublicationSignatureEs384:   data.rec.PublicationSignatureEs384,
		PublicationSignatureMldsa87: data.rec.PublicationSignatureMldsa87,
		AnchorEs384PublicKey:        data.owner.AnchorEs384PublicKey,
		AnchorMldsa87PublicKey:      data.owner.AnchorMldsa87PublicKey,
	})
}

// verifySigningKeyPublicationProof parses the canonical body, runs the hybrid signature check, and cross-checks every signed field against server-derived state
// The check is run only at write time (insert or proof-attach); once a row is stored as proven, subsequent SetPublished toggles do not re-evaluate the proof
// `as` is the AuthStore the user lookup runs against; pass `s.db.AuthStore()` outside a transaction or `tx.AuthStore()` inside one to avoid double-locking sqlite
func (s *Server) verifySigningKeyPublicationProof(ctx context.Context, as *db.AuthStore, userID, algorithm, keyLabel, keyID, payloadStr, sigEsB64, sigMlB64 string) error {
	if payloadStr == "" || sigEsB64 == "" || sigMlB64 == "" {
		return errors.New("publicationPayload, publicationSignatureEs384, and publicationSignatureMldsa87 are all required")
	}

	payload, err := protocolv2.ParseSigningKeyPublicationPayload(payloadStr)
	if err != nil {
		return fmt.Errorf("invalid canonical body: %w", err)
	}

	// Bind the payload to server-derived expected values
	if payload.V != protocolv2.SigningKeyPublicationVersion {
		return fmt.Errorf("unsupported v %d", payload.V)
	}
	if payload.UserID != userID {
		return errors.New("userId does not match session")
	}
	if payload.Algorithm != algorithm {
		return errors.New("algorithm does not match")
	}
	if payload.KeyLabel != keyLabel {
		return errors.New("keyLabel does not match")
	}
	if payload.KeyID != keyID {
		return errors.New("keyId does not match")
	}

	// Pin the signed createdAt to a ±2 minute window of server now so an old captured proof cannot be replayed
	err = payload.ValidateCreatedAt(time.Now(), signingKeyPublicationCreatedAtSkew)
	if err != nil {
		return err
	}

	// Look up the user's anchor public keys + current epoch
	owner, err := as.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("user not found")
	}
	if payload.WrappedKeyEpoch != owner.WrappedKeyEpoch {
		return fmt.Errorf("wrappedKeyEpoch %d does not match current user epoch %d", payload.WrappedKeyEpoch, owner.WrappedKeyEpoch)
	}

	// Parse the anchor public keys
	es384Pub, mldsa87PubBytes, err := parseAnchorPubkeys(owner.AnchorEs384PublicKey, owner.AnchorMldsa87PublicKey)
	if err != nil {
		return fmt.Errorf("stored anchor public key is invalid: %w", err)
	}

	// Parse the signatures
	sigEs, sigMl, err := parseHybridSignatures(sigEsB64, sigMlB64)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Verify the signatures
	err = protocolv2.VerifyHybridSigningKeyPublication(es384Pub, mldsa87PubBytes, &payload, sigEs, sigMl)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// validateSigningJWKAndPEM parses the JWK and PEM representations of a signing public key, checks that they refer to the same point, and returns the JWK thumbprint used as the canonical id along with a canonical re-serialization of the JWK
func validateSigningJWKAndPEM(jwkBytes json.RawMessage, pemStr string) (kid string, canonical []byte, err error) {
	if len(jwkBytes) == 0 {
		return "", nil, errors.New("missing jwk")
	}
	if pemStr == "" {
		return "", nil, errors.New("missing pem")
	}

	// Parse the key as JWK
	jwk, err := protocolv2.ParseECP256SigningJWK(jwkBytes)
	if err != nil {
		return "", nil, fmt.Errorf("invalid jwk: %w", err)
	}

	// Parse the key as PEM
	pemRaw, err := protocolv2.ParseECP256SigningPEM([]byte(pemStr))
	if err != nil {
		return "", nil, fmt.Errorf("invalid pem: %w", err)
	}

	// Get the public key
	// This also performs additional validations to ensure the JWK represents a valid ECDH key, on-curve
	jwkPub, err := jwk.ToECDHPublicKey()
	if err != nil {
		return "", nil, fmt.Errorf("invalid jwk: %w", err)
	}

	// Ensure the two keys are equal
	if !bytes.Equal(jwkPub.Bytes(), pemRaw) {
		return "", nil, errors.New("jwk and pem do not match")
	}

	// Compute the key ID
	kid, err = jwk.Thumbprint()
	if err != nil {
		return "", nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}

	// Re-encode the JWK in a canonical format
	canonical, err = json.Marshal(jwk)
	if err != nil {
		return "", nil, fmt.Errorf("failed to canonicalize jwk: %w", err)
	}

	return kid, canonical, nil
}
