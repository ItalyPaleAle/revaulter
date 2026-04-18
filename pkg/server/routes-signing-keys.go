package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
)

type v2SigningKeyPublishRequest struct {
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	JWK       json.RawMessage `json:"jwk"`
	PEM       string          `json:"pem"`
}

type v2SigningKeyPublishResponse struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	KeyLabel  string    `json:"keyLabel"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type v2SigningKeyUnpublishRequest struct {
	ID string `json:"id"`
}

type v2SigningKeyUnpublishResponse struct {
	Deleted bool `json:"deleted"`
}

type v2SigningKeyPublicResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	CreatedAt time.Time       `json:"createdAt"`
	JWK       json.RawMessage `json:"jwk"`
}

// RouteV2APISigningKeyList lists the current user's published signing keys
// Only metadata is returned; JWK and PEM are omitted to keep the list lean
func (s *Server) RouteV2APISigningKeyList(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	items, err := s.signingKeyStore.ListForUser(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if items == nil {
		items = []db.PublishedSigningKeyListItem{}
	}
	c.JSON(http.StatusOK, items)
}

// RouteV2APISigningKeyPublish publishes (or replaces) a signing key for the authenticated user
// The client submits both JWK and PEM — they are stored verbatim, but the server validates them and checks that the JWK thumbprint matches the PEM public point
func (s *Server) RouteV2APISigningKeyPublish(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2SigningKeyPublishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	if req.Algorithm == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing algorithm"))
		return
	}
	if !protocolv2.IsSupportedSigningAlgorithm(req.Algorithm) {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "unsupported signing algorithm %q", req.Algorithm))
		return
	}
	if req.KeyLabel == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing keyLabel"))
		return
	}
	if len(req.KeyLabel) > 128 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "keyLabel too long"))
		return
	}
	if len(req.JWK) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing jwk"))
		return
	}
	if req.PEM == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing pem"))
		return
	}

	jwk, err := protocolv2.ParseECP256SigningJWK(req.JWK)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid jwk: %v", err))
		return
	}
	pemRaw, err := protocolv2.ParseECP256SigningPEM([]byte(req.PEM))
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid pem: %v", err))
		return
	}

	jwkPub, err := jwk.ToECDHPublicKey()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid jwk: %v", err))
		return
	}
	if !bytes.Equal(jwkPub.Bytes(), pemRaw) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "jwk and pem do not match"))
		return
	}

	id, err := jwk.ThumbprintHex()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.signingKeyStore.Upsert(c.Request.Context(), db.UpsertPublishedSigningKeyInput{
		ID:        id,
		UserID:    userID,
		Algorithm: req.Algorithm,
		KeyLabel:  req.KeyLabel,
		JWK:       string(req.JWK),
		PEM:       req.PEM,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	rec, err := s.signingKeyStore.GetByID(c.Request.Context(), id)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusInternalServerError, "failed to read back published key"))
		return
	}

	c.JSON(http.StatusOK, v2SigningKeyPublishResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	})
}

// RouteV2APISigningKeyUnpublish hard-deletes a signing key publication belonging to the session user
func (s *Server) RouteV2APISigningKeyUnpublish(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2SigningKeyUnpublishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing id"))
		return
	}

	ok, err := s.signingKeyStore.Delete(c.Request.Context(), userID, req.ID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2SigningKeyUnpublishResponse{
		Deleted: ok,
	})
}

// RouteV2SigningKeyPublic serves a published signing key in the format requested by the path extension:
// - .jwk and .json return the stored JWK
// - .pem and .pub return the PEM
// The endpoint is unauthenticated and rate-limited; unknown IDs and formats return 404
func (s *Server) RouteV2SigningKeyPublic(c *gin.Context) {
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

	rec, err := s.signingKeyStore.GetByID(c.Request.Context(), id)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "not found"))
		return
	}

	// Override the cache-control as this route is cacheable
	c.Header("Cache-Control", "public, max-age=3600")

	if wantPEM {
		c.Header("Content-Type", "application/x-pem-file")
		c.String(http.StatusOK, rec.PEM)
		return
	}

	c.JSON(http.StatusOK, v2SigningKeyPublicResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		CreatedAt: rec.CreatedAt,
		JWK:       json.RawMessage(rec.JWK),
	})
}
