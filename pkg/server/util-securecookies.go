package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/italypaleale/revaulter/pkg/config"
)

const jwtIssuer = "revaulter"

func getSecureCookie(c *gin.Context, name string) (plaintextValue string, ttl time.Duration, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", 0, nil
		}
		return "", 0, err
	}
	if cookieValue == "" {
		return "", 0, fmt.Errorf("cookie %s is empty", name)
	}

	// Decrypt the encrypted JWE
	dec, err := jwe.Decrypt([]byte(cookieValue),
		jwe.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decrypt token in cookie: %w", err)
	}

	// Parse the encrypted JWT in the cookie
	token, err := jwt.Parse(dec,
		jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(cfg.AzureClientId),
		jwt.WithKey(jwa.HS256, cfg.GetCookieSigningKey()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Validate the presence of the "v" claim
	var v string
	if vI, ok := token.Get("v"); ok {
		v, ok = vI.(string)
		if !ok {
			v = ""
		}
	}
	if v == "" {
		return "", 0, errors.New("invalid value for 'v' claim")
	}

	// Get the TTL
	ttl = time.Until(token.Expiration())

	return v, ttl, nil
}

func setSecureCookie(c *gin.Context, name string, plaintextValue string, expiration time.Duration, path string, domain string, secureCookie bool, httpOnly bool) error {
	if expiration < 1 {
		return errors.New("invalid expiration value: must be greater than 0")
	}

	cfg := config.Get()

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{
			// Use the Azure client ID as our audience too
			cfg.AzureClientId,
		}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim("v", plaintextValue).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate and encrypt the JWT
	cookieValue, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256, cfg.GetCookieSigningKey())).
		Encrypt(
			jwt.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
			jwt.WithEncryptOption(jwe.WithContentEncryption(jwa.A128GCM)),
		).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	c.SetCookie(name, string(cookieValue), int(expiration.Seconds()), path, c.Request.URL.Host, secureCookie, httpOnly)

	return nil
}
