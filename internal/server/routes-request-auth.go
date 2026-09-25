package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/requestjwt"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

type v2AuthRequestAuthMethodsRequest struct {
	// Null values are unchanged
	RequestKeyEnabled  *bool `json:"requestKeyEnabled"`
	RequestOIDCEnabled *bool `json:"requestOidcEnabled"`
}

type v2AuthRequestAuthMethodsResponse struct {
	OK                 bool `json:"ok"`
	RequestKeyEnabled  bool `json:"requestKeyEnabled"`
	RequestOIDCEnabled bool `json:"requestOidcEnabled"`
}

type v2AuthAddRequestOIDCIssuerRequest struct {
	DisplayName string `json:"displayName"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`
	Subject     string `json:"subject"`
	JWKSURL     string `json:"jwksUrl"`
}

type v2AuthDeleteRequestOIDCIssuerRequest struct {
	ID string `json:"id"`
}

type v2AuthRequestOIDCIssuersResponse struct {
	OK      bool                   `json:"ok"`
	Issuers []db.RequestOIDCIssuer `json:"requestOidcIssuers"`
}

// RouteV2AuthRequestAuthMethods is the handler for POST /v2/auth/request-auth-methods
// It sets which credentials the CLI can use to authenticate requests: the static request key, JWTs from trusted OIDC issuers, or both
func (s *Server) RouteV2AuthRequestAuthMethods(c *gin.Context) {
	// Get the user ID
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
	var req v2AuthRequestAuthMethodsRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.RequestKeyEnabled == nil || req.RequestOIDCEnabled == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "requestKeyEnabled and requestOidcEnabled are required"))
		return
	}

	methods := db.RequestAuthMethods{
		RequestKey: *req.RequestKeyEnabled,
		OIDC:       *req.RequestOIDCEnabled,
	}

	// Update the methods and write the audit row atomically
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.AuthStore().UpdateRequestAuthMethods(ctx, userID, methods)
		if rErr != nil {
			return struct{}{}, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthRequestAuthMethods,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			Metadata: jsonMetadata(map[string]any{
				"requestKeyEnabled":  methods.RequestKey,
				"requestOidcEnabled": methods.OIDC,
			}),
		})
		if rErr != nil {
			return struct{}{}, rErr
		}

		return struct{}{}, nil
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Request authentication methods changed",
		slog.String("user_id", userID),
		slog.Bool("request_key", methods.RequestKey),
		slog.Bool("oidc", methods.OIDC),
	)

	// Send response
	c.JSON(http.StatusOK, v2AuthRequestAuthMethodsResponse{
		OK:                 true,
		RequestKeyEnabled:  methods.RequestKey,
		RequestOIDCEnabled: methods.OIDC,
	})
}

// RouteV2AuthAddRequestOIDCIssuer is the handler for POST /v2/auth/request-oidc-issuers/add
func (s *Server) RouteV2AuthAddRequestOIDCIssuer(c *gin.Context) {
	// Get the user ID
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body, then validate it
	var req v2AuthAddRequestOIDCIssuerRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	cfg := requestjwt.IssuerConfig{
		Issuer:   req.Issuer,
		Audience: req.Audience,
		Subject:  req.Subject,
		JWKSURL:  req.JWKSURL,
	}
	err = requestjwt.NormalizeIssuerConfig(&cfg)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid OIDC issuer: %v", err))
		return
	}

	displayName := strings.TrimSpace(req.DisplayName)
	err = validateRequestOIDCIssuerDisplayName(displayName)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid OIDC issuer: %v", err))
		return
	}

	// Store the issuer and write the audit row atomically
	type addResult struct {
		added *db.RequestOIDCIssuer
		list  []db.RequestOIDCIssuer
	}
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (addResult, error) {
		added, list, rErr := tx.AuthStore().AddRequestOIDCIssuer(ctx, userID, db.AddRequestOIDCIssuerInput{
			DisplayName: displayName,
			Issuer:      cfg.Issuer,
			Audience:    cfg.Audience,
			Subject:     cfg.Subject,
			JWKSURL:     cfg.JWKSURL,
		})
		if rErr != nil {
			return addResult{}, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthOIDCIssuerAdd,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			Metadata:     requestOIDCIssuerAuditMetadata(added),
		})
		if rErr != nil {
			return addResult{}, rErr
		}

		return addResult{added: added, list: list}, nil
	})
	if errors.Is(err, db.ErrTooManyRequestOIDCIssuers) {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusConflict, "Cannot add more than %d OIDC issuers", db.MaxRequestOIDCIssuersPerUser))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Trusted OIDC issuer added",
		slog.String("user_id", userID),
		slog.String("issuer_id", res.added.ID),
		slog.String("issuer", res.added.Issuer),
	)

	// Send response
	c.JSON(http.StatusOK, v2AuthRequestOIDCIssuersResponse{
		OK:      true,
		Issuers: res.list,
	})
}

// RouteV2AuthDeleteRequestOIDCIssuer is the handler for POST /v2/auth/request-oidc-issuers/delete
func (s *Server) RouteV2AuthDeleteRequestOIDCIssuer(c *gin.Context) {
	// Get the user ID
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
	var req v2AuthDeleteRequestOIDCIssuerRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "id is required"))
		return
	}

	// Delete and write the audit row atomically
	list, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) ([]db.RequestOIDCIssuer, error) {
		deleted, updated, rErr := tx.AuthStore().DeleteRequestOIDCIssuer(ctx, userID, req.ID)
		if rErr != nil {
			return nil, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthOIDCIssuerDelete,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			Metadata:     requestOIDCIssuerAuditMetadata(deleted),
		})
		if rErr != nil {
			return nil, rErr
		}

		return updated, nil
	})
	if errors.Is(err, db.ErrRequestOIDCIssuerNotFound) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "OIDC issuer not found"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Trusted OIDC issuer deleted",
		slog.String("user_id", userID),
		slog.String("issuer_id", req.ID),
	)

	// Send response
	c.JSON(http.StatusOK, v2AuthRequestOIDCIssuersResponse{
		OK:      true,
		Issuers: list,
	})
}

// requestOIDCIssuerAuditMetadata builds the metadata payload for the trusted issuer audit events
func requestOIDCIssuerAuditMetadata(rec *db.RequestOIDCIssuer) json.RawMessage {
	return jsonMetadata(map[string]any{
		"issuerId": rec.ID,
		"issuer":   truncateAuditValue(rec.Issuer),
		"audience": truncateAuditValue(rec.Audience),
		"subject":  truncateAuditValue(rec.Subject),
		// The JWKS URL can be long, so only record whether it's set
		"discovery": rec.JWKSURL == "",
	})
}

func validateRequestOIDCIssuerDisplayName(name string) error {
	if len(name) > requestjwt.MaxDisplayNameLength {
		return fmt.Errorf("name must be at most %d characters", requestjwt.MaxDisplayNameLength)
	}

	invalid := strings.ContainsFunc(name, func(r rune) bool {
		return !unicode.IsPrint(r)
	})
	if invalid {
		return errors.New("name contains invalid characters")
	}

	return nil
}
