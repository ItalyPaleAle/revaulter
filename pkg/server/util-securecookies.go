package server

import (
	"bytes"
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

// Retrieves a secure cookie that contains an encrypted JWT
func getSecureCookieEncryptedJWT(c *gin.Context, name string) (plaintextValue string, ttl time.Duration, err error) {
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
	value, ttl, err := validateJWT(dec, name)
	if err != nil {
		return "", 0, fmt.Errorf("token in cookie is invalid: %w", err)
	}

	return value, ttl, nil
}

// Retrieves a secure cookie that contains an Azure AD token
// This uses a custom serialization scheme because tokens issued by Azure AD can be too large for a cookie, and using an encrypted JWT makes their size balloon due to multiple rounds of base64 encoding.
func getSecureCookieEncryptedeAzureADAccessToken(c *gin.Context, name string) (plaintextValue string, ttl time.Duration, err error) {
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

	// The cookie value is the signed message and the encrypted payload, separated by a |
	signed, encrypted, ok := strings.Cut(cookieValue, "|")
	if !ok || signed == "" || encrypted == "" {
		return "", 0, errors.New("cookie is invalid: not in the expected format")
	}

	// Parse and validate the signed JWT
	value, ttl, err := validateJWT([]byte(signed), name)
	if err != nil {
		return "", 0, fmt.Errorf("signed JWT in cookie is invalid: %w", err)
	}

	// Decrypt the JWE that contains the header and payload of the access token
	dec, err := jwe.Decrypt([]byte(encrypted),
		jwe.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decrypt token in cookie: %w", err)
	}

	// The access token's header and payload are separated by a newline
	atHeader, atPayload, ok := bytes.Cut(dec, []byte{'\n'})
	if !ok || len(atHeader) == 0 || len(atPayload) == 0 {
		return "", 0, errors.New("decrypted part is not in the expected format")
	}

	// Re-construct the access token
	b := strings.Builder{}
	_, _ = b.WriteString(base64.RawURLEncoding.EncodeToString(atHeader))
	_, _ = b.WriteRune('.')
	_, _ = b.WriteString(base64.RawURLEncoding.EncodeToString(atPayload))
	_, _ = b.WriteRune('.')
	_, _ = b.WriteString(value)

	return b.String(), ttl, nil
}

func validateJWT(data []byte, name string) (value string, ttl time.Duration, err error) {
	cfg := config.Get()

	// Parse and validate the token
	token, err := jwt.Parse(data,
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
		return "", 0, errors.New("missing value for 'v' claim")
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

	// Create the JWT
	// The value is the plaintext value
	token, err := createJWT(name, plaintextValue, expiration)
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

	// Decode from base64 the atHeader and payload
	atHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("token from Azure AD is not in the correct format: failed to decode header: %w", err)
	}
	atPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("token from Azure AD is not in the correct format: failed to decode payload: %w", err)
	}

	// Make sure that the header doesn't contain a newline (it's ok if there's one in the payload however - although it hasn't been observed)
	if bytes.Contains(atHeader, []byte{'\n'}) {
		return "", errors.New("token from Azure AD is not in the correct format: header contains a \\n character")
	}

	// Claims for the JWT
	// In here, the value is just the signature of the token, which allows us to make sure the access token itself is "signed" by us
	token, err := createJWT(name, parts[2], expiration)
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

	// Encrypt the access token's header and payload (not base64-encoded), separated by a newline
	encMsg := make([]byte, len(atHeader)+len(atPayload)+1)
	copy(encMsg, atHeader)
	encMsg[len(atHeader)] = '\n'
	copy(encMsg[len(atHeader)+1:], atPayload)

	encrypted, err := jwe.Encrypt(encMsg,
		jwe.WithKey(jwa.A128KW, cfg.GetCookieEncryptionKey()),
		jwe.WithContentEncryption(jwa.A128GCM),
	)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt access token: %w", err)
	}

	// The cookie value is the signed token plus the encrypted message
	return string(signed) + "|" + string(encrypted), nil
}

func createJWT(name string, value string, expiration time.Duration) (jwt.Token, error) {
	cfg := config.Get()
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
		Claim("v", value).
		Build()
	return token, err
}
