package server

import (
	"bytes"
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

type v2SigningKeyCreateRequest struct {
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	JWK       json.RawMessage `json:"jwk"`
	PEM       string          `json:"pem"`
	Published bool            `json:"published"`
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
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type v2SigningKeySetPublishedRequest struct {
	Published bool `json:"published"`
}

type v2SigningKeyDeleteResponse struct {
	Deleted bool `json:"deleted"`
}

type v2SigningKeyDetailResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	Published bool            `json:"published"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
	JWK       json.RawMessage `json:"jwk"`
	PEM       string          `json:"pem"`
}

type v2SigningKeyPublicResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	CreatedAt time.Time       `json:"createdAt"`
	JWK       json.RawMessage `json:"jwk"`
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
// The client submits JWK and PEM — they are stored verbatim, but the server validates them and checks that the JWK thumbprint matches the PEM public point
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

	// Save in the database
	sks := s.db.SigningKeyStore()
	rec, err := sks.Create(c.Request.Context(), db.InsertSigningKeyInput{
		ID:        kid,
		UserID:    userID,
		Algorithm: req.Algorithm,
		KeyLabel:  req.KeyLabel,
		JWK:       string(canonicalJWK),
		PEM:       req.PEM,
		Published: req.Published,
	})
	if errors.Is(err, db.ErrSigningKeyAlreadyExists) {
		// Conflict on (user, algorithm, keyLabel)
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, err.Error()))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusCreated, v2SigningKeyItemResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		Published: rec.Published,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	})
}

// RouteV2APISigningKeyUpdate flips the published flag on an existing signing key owned by the session user
// Returns a 404 when the id doesn't match a row belonging to the authenticated user
func (s *Server) RouteV2APISigningKeyUpdate(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the key ID form the URL
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

	// Update in the database
	sks := s.db.SigningKeyStore()
	rec, err := sks.SetPublished(c.Request.Context(), userID, id, req.Published)
	if errors.Is(err, db.ErrSigningKeyNotFound) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusOK, v2SigningKeyItemResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		Published: rec.Published,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	})
}

// RouteV2APISigningKeyGet returns a signing key owned by the session user, including the stored JWK and PEM
// Returns 404 when the id doesn't match a row belonging to the authenticated user, so a guessed id can't probe another user's keys
func (s *Server) RouteV2APISigningKeyGet(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the key ID form the URL
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
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		Published: rec.Published,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
		JWK:       json.RawMessage(rec.JWK),
		PEM:       rec.PEM,
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

	// Get the key ID form the URL
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
// - .jwk and .json return the stored JWK
// - .pem and .pub return the PEM
// The endpoint is unauthenticated and rate-limited; unknown IDs and formats return 404
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

	// Get from the database
	sks := s.db.SigningKeyStore()
	rec, err := sks.GetPublishedByID(c.Request.Context(), id)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		// Key doesn't exist or is not published
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}

	// Override the cache-control as this route is cacheable
	c.Header("Cache-Control", "public, max-age=600")

	switch wantPEM {
	case true:
		// Respond with PEM
		c.Header("Content-Type", "application/x-pem-file")
		c.String(http.StatusOK, rec.PEM)
		return
	case false:
		// Respond with JWK
		c.JSON(http.StatusOK, v2SigningKeyPublicResponse{
			ID:        rec.ID,
			Algorithm: rec.Algorithm,
			KeyLabel:  rec.KeyLabel,
			CreatedAt: rec.CreatedAt,
			JWK:       json.RawMessage(rec.JWK),
		})
	}
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
