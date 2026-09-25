package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/requestjwt"
)

const (
	contextKeySessionTTL      = "SessionTTL"
	sessionCookieNameSecure   = "__Host-_s"
	sessionCookieNameInsecure = "_s"
	contextKeyUserID          = "UserID"
	contextKeyRequestUser     = "RequestUser"

	// Set by the request middlewares to the method the credential was authenticated with, as a db.AuditAuthMethod
	contextKeyRequestAuthMethod = "RequestAuthMethod"
	// Set by the request middlewares to the verified claims, when the credential is a JWT
	contextKeyRequestJWTClaims = "RequestJWTClaims"
)

// sessionCookieFor returns the appropriate cookie name and path for the connection
// __Host- prefix enforces Secure, no Domain, Path=/ — prevents cookie tossing from subdomains
// On insecure connections (incl. development), fall back to the unprefixed name
func sessionCookieFor(c *gin.Context) (name, path string) {
	if secureCookie(c) {
		return sessionCookieNameSecure, "/"
	}

	return sessionCookieNameInsecure, "/v2"
}

func (s *Server) MiddlewareSession(requireReady bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try bearer token first, then fall back to cookie
		token := getBearerToken(c)
		if token == "" {
			cookieName, _ := sessionCookieFor(c)
			var err error
			token, err = c.Cookie(cookieName)
			if err != nil || token == "" {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User is not authenticated"))
				return
			}
		}

		// Parse the session token and validate it
		sess, err := parseAuthSessionToken(token)
		if err != nil || sess == nil {
			if err != nil {
				_ = c.Error(fmt.Errorf("session token parse error: %w", err))
			}
			AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User session is invalid or expired"))
			return
		}

		// If we require the user to be ready, enforce that
		if requireReady && !sess.Ready {
			_ = c.Error(fmt.Errorf("session not ready for %s %s user=%s ready=%t", c.Request.Method, c.Request.URL.Path, sess.UserID, sess.Ready))
			AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "User account setup is not complete"))
			return
		}

		ttl := int(max(time.Until(sess.ExpiresAt), 0).Seconds())
		c.Set(contextKeySessionTTL, ttl)
		c.Set(contextKeyUserID, sess.UserID)
	}
}

// MiddlewareRequestKey reads the request credential from the Authorization header and retrieves the user
// The credential is either the user's static request key or a JWT signed by one of the user's trusted OIDC issuers
func (s *Server) MiddlewareRequestKey(c *gin.Context) {
	kind, credential := protocolv2.ParseAuthorization(c.GetHeader("Authorization"))

	var user *db.User
	switch kind {
	case protocolv2.CredentialRequestKey:
		user = s.authenticateRequestKey(c, credential)
	case protocolv2.CredentialJWT:
		user = s.authenticateRequestJWT(c, credential)
	case protocolv2.CredentialResultToken:
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Result tokens can only be used to retrieve the result of a request"))
		return
	case protocolv2.CredentialUnsupported:
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unsupported authorization scheme: use "+protocolv2.AuthSchemeRequestKey+" for request keys, or "+protocolv2.AuthSchemeBearer+" for OIDC tokens"))
		return
	default:
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Missing request key"))
		return
	}
	if user == nil {
		// The request was already aborted
		return
	}

	s.completeRequestAuth(c, user)
}

// MiddlewareRequestResult authenticates calls to GET /v2/request/result/:state
// It accepts the result token returned when the request was created, with the ResultToken scheme, which stays valid for the request's lifetime even after a short-lived JWT expires
// Any other credential is handled as in MiddlewareRequestKey
func (s *Server) MiddlewareRequestResult(c *gin.Context) {
	kind, token := protocolv2.ParseAuthorization(c.GetHeader("Authorization"))
	if kind != protocolv2.CredentialResultToken {
		s.MiddlewareRequestKey(c)
		return
	}

	// Load the request's result token and its owner in a single query, and check the token against the one issued for the request
	// Every mismatch returns the same error as an unknown state, so callers can't probe for another user's states
	resultTokenHash, user, err := s.db.RequestStore().GetResultTokenAndOwner(c.Request.Context(), c.Param("state"))
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil || user.Status != "active" || !resultTokenMatches(token, resultTokenHash) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "State not found or expired"))
		return
	}

	s.completeRequestAuth(c, user)
}

// authenticateRequestKey returns the user that owns the static request key
// If the key isn't valid, it aborts the request and returns nil
func (s *Server) authenticateRequestKey(c *gin.Context, requestKey string) *db.User {
	// Get the user matching the request key from the database
	// Note: this is not performed in a transaction because we can't easily make a transaction that spans this middleware and the handlers that use it
	// However, handlers that use this middleware do not modify the auth store
	user, err := s.db.AuthStore().GetUserByRequestKey(c.Request.Context(), requestKey)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return nil
	}
	if user == nil || user.Status != "active" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request key not found"))
		return nil
	}

	// Users can disable the static request key, for example when they only use OIDC tokens
	if !user.RequestAuthMethods.RequestKey {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request key authentication is disabled for this user"))
		return nil
	}

	c.Set(contextKeyRequestAuthMethod, db.AuditAuthMethodRequestKey)

	return user
}

// completeRequestAuth runs the checks shared by every request credential, then stores the user in the context
func (s *Server) completeRequestAuth(c *gin.Context, user *db.User) {
	// The X-Revaulter-User header is required with JWTs, and optional otherwise
	// When it's set, it must name the user the credential belongs to, so a misconfigured client fails instead of reaching another user
	headerUserID := c.GetHeader(protocolv2.UserIDHeader)
	if headerUserID != "" && headerUserID != user.ID {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "The "+protocolv2.UserIDHeader+" header does not match the user the credential belongs to"))
		return
	}

	// User must be ready
	if !user.Ready {
		AbortWithErrorJSON(c, NewResponseError(http.StatusPreconditionFailed, "User account setup is not complete"))
		return
	}

	// Check if the client IP is allowed (if there's an allowlist)
	if !clientIPAllowed(c, user.AllowedIPs) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "This client's IP is not allowed to perform this request"))
		return
	}

	// Set the user in the context
	c.Set(contextKeyRequestUser, user)
}

func getRequestUserFromCtx(c *gin.Context) *db.User {
	val, ok := c.Get(contextKeyRequestUser)
	if !ok {
		return nil
	}

	user, ok := val.(*db.User)
	if !ok {
		return nil
	}

	return user
}

// getRequestAuthMethodFromCtx returns how the request credential was authenticated
func getRequestAuthMethodFromCtx(c *gin.Context) db.AuditAuthMethod {
	val, ok := c.Get(contextKeyRequestAuthMethod)
	if !ok {
		return ""
	}

	method, ok := val.(db.AuditAuthMethod)
	if !ok {
		return ""
	}

	return method
}

// getRequestJWTClaimsFromCtx returns the verified claims of the request credential, when it's a JWT
func getRequestJWTClaimsFromCtx(c *gin.Context) *requestjwt.Claims {
	val, ok := c.Get(contextKeyRequestJWTClaims)
	if !ok {
		return nil
	}

	claims, ok := val.(*requestjwt.Claims)
	if !ok {
		return nil
	}

	return claims
}

// getBearerToken extracts a bearer token from the Authorization header.
// Returns empty string if no bearer token is present.
func getBearerToken(c *gin.Context) string {
	const bearerPrefix = "bearer "

	h := c.GetHeader("Authorization")

	// Remove the bearer prefix
	if len(h) > len(bearerPrefix) && strings.ToLower(h[0:len(bearerPrefix)]) == bearerPrefix {
		return h[len(bearerPrefix):]
	}

	return ""
}
