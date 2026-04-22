package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/db"
)

const (
	contextKeySessionTTL      = "SessionTTL"
	sessionCookieNameSecure   = "__Host-_s"
	sessionCookieNameInsecure = "_s"
	contextKeyUserID          = "UserID"
	contextKeyRequestUser     = "RequestUser"
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

		sess, err := parseAuthSessionToken(token)
		if err != nil || sess == nil {
			if err != nil {
				_ = c.Error(fmt.Errorf("session token parse error: %w", err))
			}
			AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User session is invalid or expired"))
			return
		}

		userID := sess.UserID
		if requireReady && !sess.Ready {
			_ = c.Error(fmt.Errorf("session not ready for %s %s user=%s ready=%t", c.Request.Method, c.Request.URL.Path, userID, sess.Ready))
			AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "User account setup is not complete"))
			return
		}

		ttl := int(max(time.Until(sess.ExpiresAt), 0).Seconds())
		c.Set(contextKeySessionTTL, ttl)
		c.Set(contextKeyUserID, userID)
	}
}

// MiddlewareRequestKey gets the request key from the params and retrieves the user
func (s *Server) MiddlewareRequestKey(c *gin.Context) {
	// Get the request key from the URL parameter
	requestKey := c.Param("requestKey")
	if requestKey == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing request key"))
		return
	}

	// Get the user
	user, err := s.authStore.GetUserByRequestKey(c.Request.Context(), requestKey)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil || user.Status != "active" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request key not found"))
		return
	}
	if !user.Ready {
		AbortWithErrorJSON(c, NewResponseError(http.StatusPreconditionFailed, "User account setup is not complete"))
		return
	}

	// Check if the client IP is allowed
	if !clientIPAllowed(c.ClientIP(), user.AllowedIPs) {
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

// getBearerToken extracts a bearer token from the Authorization header.
// Returns empty string if no bearer token is present.
func getBearerToken(c *gin.Context) string {
	const bearerPrefix = "bearer "

	h := c.GetHeader("Authorization")

	// Remove the bearer prefix
	if len(h) > len(bearerPrefix)+1 && strings.ToLower(h[0:len(bearerPrefix)]) == bearerPrefix {
		return h[len(bearerPrefix):]
	}

	return ""
}
