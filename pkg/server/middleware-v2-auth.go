package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/config"
)

const (
	headerSessionTTL             = "x-session-ttl"
	v2SessionCookieName          = "_v2s"
	contextKeyV2SessionID        = "v2SessionID"
	contextKeyV2AdminID          = "v2AdminID"
	contextKeyV2AdminUsername    = "v2AdminUsername"
	contextKeyV2PasswordVerified = "v2PasswordVerified"
	contextKeyV2SessionExpiry    = "v2SessionExpiry"
)

func (s *Server) V2SessionMiddleware(required bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.v2AuthStore == nil {
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
			}
			return
		}

		sessID, ttl, err := getSecureCookieEncryptedJWT(c, v2SessionCookieName)
		if err != nil || sessID == "" {
			if err != nil {
				_ = c.Error(fmt.Errorf("cookie error: %w", err))
			}
			if required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User is not authenticated"))
			}
			return
		}

		sess, err := s.v2AuthStore.GetSession(c.Request.Context(), sessID)
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
		c.Set(contextKeyV2SessionID, sess.ID)
		c.Set(contextKeyV2AdminID, sess.AdminID)
		c.Set(contextKeyV2AdminUsername, sess.Username)
		c.Set(contextKeyV2PasswordVerified, sess.PasswordVerified)
		c.Set(contextKeyV2SessionExpiry, sess.ExpiresAt)
	}
}

func (s *Server) V2PasswordFactorRequiredMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.Get().PasswordFactorMode != "required" {
			return
		}
		v, _ := c.Get(contextKeyV2PasswordVerified)
		ok, _ := v.(bool)
		if !ok {
			AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Password factor verification is required"))
			return
		}
	}
}
