package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/gin-gonic/gin"
	"golang.org/x/text/unicode/norm"

	"github.com/italypaleale/revaulter/pkg/config"
)

const (
	// Name of the auth state cookie
	authStateCookieName = "_auth_state"
	// Max Age for the auth state cookie
	authStateCookieMaxAge = 5 * time.Minute
	// Name of the Access Token cookie
	atCookieName = "_at"
)

// AccessToken contains the details of the access token
type AccessToken struct {
	TokenType        string `json:"token_type"`
	Resource         string `json:"resource"`
	Scope            string `json:"scope"`
	ExpiresIn        int    `json:"expires_in"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RouteAuthSignin is the handler for the GET /auth/signin request
// This redirects the user to the page where they can sign in
func (s *Server) RouteAuthSignin(c *gin.Context) {
	cfg := config.Get()

	// Check if we already have a state cookie that was issued recently
	// It can happen that clients are redirected to the auth page more than once at the same time
	seed, ttl, err := getSecureCookie(c, authStateCookieName)
	if err != nil || seed == "" || ttl < (authStateCookieMaxAge-time.Minute) {
		// Generate a random seed
		b := make([]byte, 12)
		_, err = io.ReadFull(rand.Reader, b)
		if err != nil {
			AbortWithErrorJSON(c, fmt.Errorf("failed to generate random seed: %w", err))
			return
		}
		seed = base64.RawURLEncoding.EncodeToString(b)
	}

	// Build the state object
	stateToken, err := createStateToken(c, seed)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to create state token: %w", err))
		return
	}

	// Set the auth state as a secure cookie
	// This may reset the existing cookie
	secureCookie := cfg.ForceSecureCookies || c.Request.URL.Scheme == "https:"
	err = setSecureCookie(c, authStateCookieName, seed, authStateCookieMaxAge, "/auth", c.Request.URL.Host, secureCookie, true, serializeSecureCookieEncryptedJWT)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set auth state secure cookie: %w", err))
		return
	}

	// Use the seed also as code verifier for the PKCE challenge
	// Compute the SHA-256 hash of that as code_challenge
	// See: https://datatracker.ietf.org/doc/html/rfc7636
	codeChallenge := sha256.Sum256([]byte(seed))

	// Build the redirect URL
	tenantId := cfg.AzureTenantId
	qs := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{cfg.AzureClientId},
		"redirect_uri":          []string{s.getBaseURL() + "/auth/confirm"},
		"response_mode":         []string{"query"},
		"state":                 []string{stateToken},
		"scope":                 []string{"https://vault.azure.net/user_impersonation"},
		"domain_hint":           []string{tenantId},
		"code_challenge_method": []string{"S256"},
		"code_challenge":        []string{base64.RawURLEncoding.EncodeToString(codeChallenge[:])},
	}

	// Redirect
	c.Redirect(http.StatusTemporaryRedirect, "https://login.microsoftonline.com/"+tenantId+"/oauth2/v2.0/authorize?"+qs.Encode())
}

// RouteAuthConfirm is the handler for the GET /auth/confirm request
// This exchanges an authorization code for an access token
func (s *Server) RouteAuthConfirm(c *gin.Context) {
	cfg := config.Get()

	// Ensure we have the required params in the query string
	code := c.Query("code")
	if code == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Parameter code is missing in the request"))
		return
	}
	// Note that this is the auth state token, not the state of the operation
	stateToken := c.Query("state")
	if stateToken == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Parameter state is missing in the request"))
		return
	}

	// Ensure that the user has the auth state cookie
	seed, _, err := getSecureCookie(c, authStateCookieName)
	if err == nil && seed == "" {
		err = errors.New("auth state cookie is missing")
	}
	if err != nil {
		_ = c.Error(fmt.Errorf("failed to retrieve auth state cookie: %w", err))
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Auth state cookie is missing or invalid"))
		return
	}

	// Unset the auth state cookie
	secureCookie := cfg.ForceSecureCookies || c.Request.URL.Scheme == "https:"
	c.SetCookie(authStateCookieName, "", -1, "/auth", c.Request.URL.Host, secureCookie, true)

	// Validate the state token
	if !validateStateToken(c, stateToken, seed) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "The state token could not be validated"))
		return
	}

	// Exchange the code for an access token
	accessToken, err := s.requestAccessToken(c.Request.Context(), code, seed)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to obtain access token: %w", err))
		return
	}

	// Expiration is the minimum of the session timeout set in the config, and the token's expiration
	expiration := cfg.SessionTimeout
	if accessToken.ExpiresIn > 0 && int(expiration.Seconds()) > accessToken.ExpiresIn {
		expiration = time.Duration(accessToken.ExpiresIn) * time.Second
	}

	// Set the access token in a cookie
	err = setSecureCookie(c, atCookieName, accessToken.AccessToken, expiration, "/", c.Request.URL.Host, secureCookie, true, serializeSecureCookieEncryptedJWT)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set access token secure cookie: %w", err))
		return
	}

	// Redirect the user to the main page
	c.Redirect(http.StatusTemporaryRedirect, s.getBaseURL())
}

func (s *Server) requestAccessToken(ctx context.Context, code, seed string) (*AccessToken, error) {
	cfg := config.Get()

	// Build the request
	data := url.Values{
		"code":          []string{code},
		"client_id":     []string{cfg.AzureClientId},
		"redirect_uri":  []string{s.getBaseURL() + "/auth/confirm"},
		"scope":         []string{"https://vault.azure.net/user_impersonation"},
		"grant_type":    []string{"authorization_code"},
		"code_verifier": []string{seed}, // For PKCE
	}
	if cfg.AzureClientSecret != "" {
		data["client_secret"] = []string{cfg.AzureClientSecret}
	} else if s.federatedIdentityCredential != nil {
		// Get the client assertion
		clientAssertion, err := s.federatedIdentityCredential.GetToken(ctx, policy.TokenRequestOptions{
			// This is a constant value
			Scopes: []string{"api://AzureADTokenExchange"},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to obtain client assertion: %w", err)
		}

		// This is a constant value
		data["client_assertion_type"] = []string{"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}
		data["client_assertion"] = []string{clientAssertion.Token}
	}

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", "https://login.microsoftonline.com/"+cfg.AzureTenantId+"/oauth2/v2.0/token", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Parse the response as JSON
	token := &AccessToken{}
	err = json.NewDecoder(res.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	if token.Error != "" {
		return nil, errors.New("error in token (" + token.Error + "): " + token.ErrorDescription)
	}
	if token.TokenType != "Bearer" {
		return nil, errors.New("invalid token type: " + token.TokenType)
	}
	if token.Scope == "" {
		return nil, errors.New("empty scope in token")
	}
	if token.AccessToken == "" {
		return nil, errors.New("empty access_token in token")
	}

	return token, nil
}

func createStateToken(c *gin.Context, seed string) (stateToken string, err error) {
	tokenSigningKey := config.Get().GetTokenSigningKey()
	if len(tokenSigningKey) == 0 {
		// Should never happen
		return "", errors.New("tokenSigningKey is empty in the configuration")
	}

	// Base string to hash
	baseStr := stateTokenBaseParts(c, seed)

	// Calculate the HMAC
	h := hmac.New(sha256.New224, []byte(tokenSigningKey))
	h.Write([]byte(baseStr))
	res := h.Sum(nil)

	// Return the hash encoded as base64url
	return base64.RawURLEncoding.EncodeToString(res), nil
}

func validateStateToken(c *gin.Context, stateToken string, seed string) bool {
	tokenSigningKey := config.Get().GetTokenSigningKey()
	if len(tokenSigningKey) == 0 {
		// Should never happen
		return false
	}

	// Decode the base64url-encoded hash
	stateTokenRaw, err := base64.RawURLEncoding.DecodeString(stateToken)
	if err != nil || len(stateTokenRaw) == 0 {
		return false
	}

	// Base string to hash
	baseStr := stateTokenBaseParts(c, seed)

	// Calculate the HMAC
	h := hmac.New(sha256.New224, []byte(tokenSigningKey))
	h.Write([]byte(baseStr))
	res := h.Sum(nil)

	// Check if equal
	return hmac.Equal(res, stateTokenRaw)
}

func stateTokenBaseParts(c *gin.Context, seed string) string {
	return strings.Join([]string{
		strings.ToLower(norm.NFKD.String(c.GetHeader("user-agent"))),
		strings.ToLower(norm.NFKD.String(c.GetHeader("accept-language"))),
		strings.ToLower(norm.NFKD.String(c.GetHeader("dnt"))),
		seed,
	}, "|")
}
