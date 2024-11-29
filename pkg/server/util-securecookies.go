package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/italypaleale/revaulter/pkg/config"
)

const (
	jwtIssuer    = "revaulter"
	maxCookieLen = 4 << 10 // 4KB is the max size for cookies browsers will accept
)

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
		jwt.WithAudience("revaulter-"+cfg.AzureClientId),
		jwt.WithKey(jwa.HS256, cfg.GetCookieSigningKey()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Validate that the name claim matches
	var n string
	if nI, ok := token.Get("n"); ok {
		n, ok = nI.(string)
		if !ok {
			n = ""
		}
	}
	if n != name {
		return "", 0, fmt.Errorf("invalid value for 'n' claim: expected '%s' but got '%s'", name, n)
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

type serializeSecureCookieFn func(name string, plaintextValue string, expiration time.Duration) (string, error)

func setSecureCookie(c *gin.Context, name string, plaintextValue string, expiration time.Duration, path string, domain string, secureCookie bool, httpOnly bool, serializeFn serializeSecureCookieFn) error {
	if expiration < 1 {
		return errors.New("invalid expiration value: must be greater than 0")
	}

	// Serialize the cookie
	cookieValue, err := serializeFn(name, plaintextValue, expiration)
	if err != nil {
		return fmt.Errorf("failed to serialize cookie: %w", err)
	}

	// Most browsers limit the size of cookies to as low as 4KB, and silently reject them
	// If the cookie is larger than 4KB, return an error
	if len(cookieValue) > maxCookieLen {
		return fmt.Errorf("cookie value exceeds the 4KB limit: %d", len(cookieValue))
	}

	// Set the cookie
	c.SetCookie(name, string(cookieValue), int(expiration.Seconds()), path, c.Request.URL.Host, secureCookie, httpOnly)

	return nil
}

// Serializes a secure cookie using an encrypted JWT
func serializeSecureCookieEncryptedJWT(name string, plaintextValue string, expiration time.Duration) (string, error) {
	cfg := config.Get()

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{
			// Use the Azure client ID as our audience too
			"revaulter-" + cfg.AzureClientId,
		}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim("n", name).
		Claim("v", plaintextValue).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
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
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	// If the cookie is larger than 4KB, we try re-generating it with compression
	if len(cookieValue) > maxCookieLen {
		cookieValue, err = jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.HS256, cfg.GetCookieSigningKey())).
			Encrypt(
				jwt.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
				jwt.WithEncryptOption(jwe.WithContentEncryption(jwa.A128GCM)),
				jwt.WithEncryptOption(jwe.WithCompress(jwa.Deflate)),
			).
			Serialize(token)
		if err != nil {
			return "", fmt.Errorf("failed to serialize token: %w", err)
		}

		// If the cookie is still larger than 4KB, return an error
		if len(cookieValue) > maxCookieLen {
			return "", fmt.Errorf("cookie value exceeds the 4KB limit: %d", len(cookieValue))
		}
	}

	return string(cookieValue), nil
}

// Serializes a secure cookie for an Azure AD access token
// Access tokens issued by Azure AD can be *very* large
// If we try to put the token in an encrypted JWT, the data would get serialized to base64 multiple times, making the size of the token balloon
// This is a problem because we save our tokens in cookies, and browsers reject cookies that are larger than 4KB
// As a solution, we use JWE to encrypt a custom payload so we can avoid some iterations of base64
func serializeSecureCookieAzureADAccessToken(name string, plaintextValue string, expiration time.Duration) (string, error) {
	cfg := config.Get()

	// First, split the token to get the 3 parts: header, payload, signature
	parts := strings.Split(plaintextValue, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token from Azure AD is not in the correct format: has %d parts instead of 3", len(parts))
	}

	// Decode from base64 the header and payload
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("token from Azure AD is not in the correct format: failed to decode header: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("token from Azure AD is not in the correct format: failed to decode payload: %w", err)
	}

	// Claims for the JWT
	// In here, the value is just the signature of the token
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{
			// Use the Azure client ID as our audience too
			"revaulter-" + cfg.AzureClientId,
		}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim("n", name).
		Claim("v", parts[2]).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate the JWT
	signed, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256, cfg.GetCookieSigningKey())).
		Serialize(token)
	if err != nil {
		return "", fmt.Errorf("failed to serialize signed token: %w", err)
	}

	// Encrypt the access token's header and payload
	encMsg := make([]byte, len(header)+len(payload)+1)
	copy(encMsg, header)
	encMsg[len(header)] = '.'
	copy(encMsg[len(header)+1:], payload)

	encrypted, err := jwe.Encrypt(encMsg,
		jwe.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
		jwe.WithContentEncryption(jwa.A128GCM),
	)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt access token: %w", err)
	}

	// The cookie value is the signed token plus the encrypted message
	return string(signed) + "." + string(encrypted), nil
}
