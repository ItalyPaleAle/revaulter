package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/text/unicode/norm"

	"github.com/italypaleale/unlocker/pkg/config"
	"github.com/italypaleale/unlocker/pkg/utils"
)

const (
	// Name of the CSRF cookie
	csrfCookieName = "_csrf_state"
	// Max Age for the CSRF cookie
	csrfCookieMaxAge = 5 * time.Minute
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

// RouteAuth is the handler for the GET /auth request
// This redirects the user to the page where they can sign in
func (s *Server) RouteAuth(c *gin.Context) {
	// Build the state object
	stateToken, seed, err := createStateToken(c)
	if err != nil {
		_ = c.Error(err)
		c.JSON(http.StatusInternalServerError, InternalServerError)
		return
	}

	// Set the seed as cookie
	secureCookie := c.Request.URL.Scheme == "https:"
	c.SetCookie(csrfCookieName, seed, int(csrfCookieMaxAge.Seconds()), "/", c.Request.URL.Host, secureCookie, true)

	// Build the redirect URL
	tenantId := viper.GetString(config.KeyAzureTenantId)
	qs := url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{viper.GetString(config.KeyAzureClientId)},
		"redirect_uri":  []string{viper.GetString(config.KeyBaseUrl) + "/auth/confirm"},
		"response_mode": []string{"query"},
		"state":         []string{stateToken},
		"scope":         []string{"https://vault.azure.net/user_impersonation"},
		"domain_hint":   []string{tenantId},
	}

	// Redirect
	c.Redirect(http.StatusTemporaryRedirect, "https://login.microsoftonline.com/"+tenantId+"/oauth2/v2.0/authorize?"+qs.Encode())
}

// RouteAuthConfirm is the handler for the GET /auth/confirm request
// This exchanges an authorization code for an access token
func (s *Server) RouteAuthConfirm(c *gin.Context) {
	// Ensure we have the required params in the querystring
	code := c.Query("code")
	if code == "" {
		_ = c.Error(errors.New("Parameter code is missing in the request"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Parameter code is missing in the request"))
		return
	}
	// Note that this is the auth stateToken, not the stateToken of the operation
	stateToken := c.Query("state")
	if stateToken == "" {
		_ = c.Error(errors.New("Parameter state is missing in the request"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("Parameter state is missing in the request"))
		return
	}

	// Ensure that the user has the CSRF cookie
	seed, _ := c.Cookie(csrfCookieName)
	if seed == "" {
		_ = c.Error(errors.New("CSRF cookie is missing or invalid"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("CSRF cookie is missing or invalid"))
		return
	}

	// Unset the CSRF cookie
	secureCookie := c.Request.URL.Scheme == "https:"
	c.SetCookie(csrfCookieName, "", -1, "/", c.Request.URL.Host, secureCookie, true)

	// Validate the state token
	if !validateStateToken(c, stateToken, seed) {
		_ = c.Error(errors.New("State token could not be validated"))
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse("The state token could not be validated"))
		return
	}

	// Exchange the code for an access token
	accessToken, err := s.requestAccessToken(c.Request.Context(), code)
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse("Error obtaining access token"))
		return
	}

	// Set the access token in a cookie
	maxAge := viper.GetInt(config.KeySessionTimeout)
	err = setSecureCookie(c, atCookieName, accessToken.AccessToken, maxAge, "/", c.Request.URL.Host, secureCookie, true)
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, InternalServerError)
		return
	}

	// Redirect the user to the main page
	c.Redirect(http.StatusTemporaryRedirect, viper.GetString(config.KeyBaseUrl))
}

func (s *Server) requestAccessToken(ctx context.Context, code string) (*AccessToken, error) {
	// Build the request
	data := url.Values{
		"code":          []string{code},
		"client_id":     []string{viper.GetString(config.KeyAzureClientId)},
		"client_secret": []string{viper.GetString(config.KeyAzureClientSecret)},
		"redirect_uri":  []string{viper.GetString(config.KeyBaseUrl) + "/auth/confirm"},
		"scope":         []string{"https://vault.azure.net/user_impersonation"},
		"grant_type":    []string{"authorization_code"},
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", "https://login.microsoftonline.com/"+viper.GetString(config.KeyAzureTenantId)+"/oauth2/v2.0/token", body)
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

func createStateToken(c *gin.Context) (stateToken string, seed string, err error) {
	tokenSigningKey := viper.GetString(config.KeyInternalTokenSigningKey)
	if tokenSigningKey == "" {
		// Should never happen
		return "", "", errors.New("tokenSigningKey is empty in the configuration")
	}

	// Random seed
	seed, err = utils.RandomString()
	if err != nil {
		return "", "", err
	}

	// Base string to hash
	baseStr := stateTokenBaseParts(c)

	// Calculate the HMAC
	h := hmac.New(sha256.New224, []byte(tokenSigningKey))
	h.Write([]byte(baseStr))
	res := h.Sum(nil)

	// Return the hash encoded as base64url
	return base64.RawURLEncoding.EncodeToString(res), seed, nil
}

func validateStateToken(c *gin.Context, stateToken string, seed string) bool {
	tokenSigningKey := viper.GetString(config.KeyInternalTokenSigningKey)
	if tokenSigningKey == "" {
		// Should never happen
		return false
	}

	// Decode the base64url-encoded hash
	stateTokenRaw, err := base64.RawURLEncoding.DecodeString(stateToken)
	if err != nil || len(stateTokenRaw) == 0 {
		return false
	}

	// Base string to hash
	baseStr := stateTokenBaseParts(c)

	// Calculate the HMAC
	h := hmac.New(sha256.New224, []byte(tokenSigningKey))
	h.Write([]byte(baseStr))
	res := h.Sum(nil)

	// Check if equal
	return hmac.Equal(res, stateTokenRaw)
}

func stateTokenBaseParts(c *gin.Context) string {
	return strings.Join([]string{
		strings.ToLower(norm.NFKD.String(c.GetHeader("user-agent"))),
		strings.ToLower(norm.NFKD.String(c.GetHeader("accept-language"))),
		strings.ToLower(norm.NFKD.String(c.GetHeader("dnt"))),
	}, "|")
}
