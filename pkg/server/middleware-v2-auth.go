package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	headerSessionTTL           = "x-session-ttl"
	sessionCookieName          = "_s"
	contextKeySessionID        = "SessionID"
	contextKeyAdminID          = "AdminID"
	contextKeyAdminUsername    = "AdminUsername"
	contextKeySessionExpiry    = "SessionExpiry"
)

func (s *Server) V2SessionMiddleware(required bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authStore == nil {
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "auth is not configured"))
			}
			return
		}

		sessID, ttl, err := getSecureCookieEncryptedJWT(c, sessionCookieName)
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
		c.Set(contextKeyAdminID, sess.AdminID)
		c.Set(contextKeyAdminUsername, sess.Username)
		c.Set(contextKeySessionExpiry, sess.ExpiresAt)
	}
}

