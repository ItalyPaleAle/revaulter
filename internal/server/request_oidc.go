package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/requestjwt"
	"github.com/italypaleale/revaulter/internal/utils"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
	// resultTokenPrefix is prepended to result tokens, so leaked tokens are easy to recognize
	resultTokenPrefix = "rvr_"

	// requestJWTVerifyTimeout bounds the time spent verifying a JWT, including fetching the issuer's keys
	requestJWTVerifyTimeout = 15 * time.Second
)

var (
	errRequestJWTUserNotFound     = errors.New("user not found, not active, or OIDC authentication disabled")
	errRequestJWTNoMatchingIssuer = errors.New("none of the user's trusted OIDC issuers matches the token")
)

// authenticateRequestJWT returns the user named in the X-Revaulter-User header, if the JWT is accepted by one of the user's trusted OIDC issuers
func (s *Server) authenticateRequestJWT(c *gin.Context, token string) *db.User {
	userID := c.GetHeader(protocolv2.UserIDHeader)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Missing "+protocolv2.UserIDHeader+" header: it must be set to the ID of the user when authenticating with a JWT"))
		return nil
	}

	// Parse the claims without verifying them first, so malformed tokens are rejected before looking up the user
	// The unverified claims are only used to narrow down the trusted issuers to verify the token against
	peek, err := requestjwt.PeekClaims(token)
	if err != nil {
		rejectRequestJWT(c, userID, err)
		return nil
	}

	// A failure to load the user is an internal error, not a problem with the token
	user, err := s.db.AuthStore().GetUserByID(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return nil
	}
	if user == nil || user.Status != "active" || !user.RequestAuthMethods.OIDC {
		rejectRequestJWT(c, userID, errRequestJWTUserNotFound)
		return nil
	}

	claims, err := s.verifyRequestJWT(c.Request.Context(), user, peek, token)
	if err != nil {
		rejectRequestJWT(c, userID, err)
		return nil
	}

	c.Set(contextKeyRequestAuthMethod, db.AuditAuthMethodRequestOIDC)
	c.Set(contextKeyRequestJWTClaims, claims)

	return user
}

// rejectRequestJWT logs why a JWT was rejected, and aborts the request with a 401
func rejectRequestJWT(c *gin.Context, userID string, err error) {
	level := slog.LevelInfo
	if errors.Is(err, requestjwt.ErrKeyFetch) {
		// The issuer's keys couldn't be retrieved, which the operator may need to act on
		level = slog.LevelWarn
	}
	logging.LogFromContext(c.Request.Context()).Log(c.Request.Context(), level, "Rejected request JWT",
		slog.Any("error", err),
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	// The response doesn't say why the token was rejected
	AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Request token is invalid or not trusted"))
}

// verifyRequestJWT checks the token against the user's trusted OIDC issuers whose issuer, audience, and subject match the unverified claims in peek, and returns the verified claims
func (s *Server) verifyRequestJWT(parentCtx context.Context, user *db.User, peek *requestjwt.Claims, token string) (*requestjwt.Claims, error) {
	ctx, cancel := context.WithTimeout(parentCtx, requestJWTVerifyTimeout)
	defer cancel()

	// Try every matching issuer entry until one accepts the token
	// Entries can differ in their JWKS URL, so a failure with one doesn't rule out the others
	var lastErr error
	for _, iss := range user.RequestOIDC {
		if iss.Issuer != peek.Issuer || !slices.Contains(peek.Audience, iss.Audience) || !requestjwt.MatchSubject(iss.Subject, peek.Subject) {
			continue
		}

		claims, err := s.requestJWT.Verify(ctx, token, requestjwt.IssuerConfig{
			Issuer:   iss.Issuer,
			Audience: iss.Audience,
			Subject:  iss.Subject,
			JWKSURL:  iss.JWKSURL,
		})
		if err != nil {
			lastErr = err
			continue
		}

		return claims, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("%w: issuer=%q subject=%q audience=%q", errRequestJWTNoMatchingIssuer, peek.Issuer, peek.Subject, peek.Audience)
}

// newResultToken generates a result token, and returns it with the hash stored in the database
func newResultToken() (token string, hash string, err error) {
	random, err := utils.RandomString(32)
	if err != nil {
		return "", "", err
	}

	token = resultTokenPrefix + random
	return token, utils.SHA256Hex([]byte(token)), nil
}

// resultTokenMatches returns true if token is the result token whose hash is stored in expectedHash
func resultTokenMatches(token string, expectedHash string) bool {
	// Requests created before result tokens existed have no hash
	if expectedHash == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(utils.SHA256Hex([]byte(token))), []byte(expectedHash)) == 1
}
