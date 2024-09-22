package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	headerSessionTTL             = "x-session-ttl"
	contextKeySessionAccessToken = "sessionAccessToken"
	contextKeySessionExpiration  = "sessionExpiration"
)

type AccessTokenMiddlewareOpts struct {
	// If true, the request fails if the token is not present
	Required bool
	// If true, allows reading an access token directly from the Authorization header, as a Bearer token
	// This is an access token with permissions on Azure Key Vault directly
	AllowAccessTokenInHeader bool
}

// AccessTokenMiddleware is a middleware that requires the user to be authenticated and present a cookie with the access token for Azure Key Vault
// Note that this middleware doesn't validate the access token in any way (not even making sure it's a valid JWT), it just ensures the token is present; it's Azure Key Vault's responsibility to validate the token
// This injects the token in the request's context if it exists and it's valid
func (s *Server) AccessTokenMiddleware(opts AccessTokenMiddlewareOpts) func(c *gin.Context) {
	return func(c *gin.Context) {
		// First, check if there's an Authorization header with a bearer token, if that's allowed for this request
		if opts.AllowAccessTokenInHeader {
			authHeader := c.GetHeader("Authorization")
			// Require the "bearer" prefix
			if len(authHeader) > 7 && strings.ToLower(authHeader[0:7]) == "bearer " {
				// Set the access token in the context
				// Set the expiration to an arbitrary 5 minutes from now, as that's relevant for the SDK only
				c.Set(contextKeySessionAccessToken, authHeader[7:])
				c.Set(contextKeySessionExpiration, time.Now().Add(5*time.Minute))
				return
			}
		}

		// Get the cookie and parse it
		at, ttl, err := getSecureCookie(c, atCookieName)
		if err != nil || at == "" {
			if err != nil {
				_ = c.Error(fmt.Errorf("cookie error: %w", err))
			}
			if opts.Required {
				AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "User is not authenticated or there's no access token in the cookies"))
			}
			return
		}

		// Set the TTL in the header
		c.Header(headerSessionTTL, strconv.Itoa(int(ttl.Seconds())))

		// Set the values in the context
		c.Set(contextKeySessionAccessToken, at)
		c.Set(contextKeySessionExpiration, time.Now().Add(ttl))
	}
}
