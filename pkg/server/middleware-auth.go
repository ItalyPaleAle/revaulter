package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	headerSessionTTL          = "x-session-ttl"
	sessionCookieNameSecure   = "__Host-_s"
	sessionCookieNameInsecure = "_s"
	contextKeySessionID       = "SessionID"
	contextKeyUserID          = "UserID"
	contextKeyUserDisplayName = "UserDisplayName"
	contextKeySessionExpiry   = "SessionExpiry"
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

func (s *Server) MiddlewareSession(required bool, requireReady bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authStore == nil {
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "auth is not configured"))
			}
			return
		}

		cookieName, _ := sessionCookieFor(c)
		sessID, ttl, err := getSecureCookieEncryptedJWT(c, cookieName)
		if err != nil || sessID == "" {
			if err != nil {
				_ = c.Error(fmt.Errorf("cookie error: %w", err))
			}
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User is not authenticated"))
			}
			return
		}

		sess, err := s.authStore.GetSession(c.Request.Context(), sessID)
		if err != nil || sess == nil {
			if err != nil {
				_ = c.Error(fmt.Errorf("session lookup error: %w", err))
			}
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User session is invalid or expired"))
			}
			return
		}
		if requireReady && !sess.Ready {
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "User account setup is not complete"))
			}
			return
		}

		// Use the minimum of cookie TTL and DB TTL.
		dbTTL := time.Until(sess.ExpiresAt)
		if dbTTL < ttl {
			ttl = dbTTL
		}
		if ttl < 0 {
			ttl = 0
		}
		c.Header(headerSessionTTL, strconv.Itoa(int(ttl.Seconds())))
		c.Set(contextKeySessionID, sess.ID)
		c.Set(contextKeyUserID, sess.UserID)
		c.Set(contextKeyUserDisplayName, sess.DisplayName)
		c.Set(contextKeySessionExpiry, sess.ExpiresAt)
	}
}
