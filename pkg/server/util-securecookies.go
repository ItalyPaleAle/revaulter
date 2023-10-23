package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"github.com/italypaleale/revaulter/pkg/config"
)

const jwtIssuer = "revaulter"

func getSecureCookie(c *gin.Context, name string) (plaintextValue string, ttl time.Duration, err error) {
	cek, ok := viper.Get(config.KeyInternalCookieEncryptionKey).(jwk.Key)
	if !ok || cek == nil {
		return "", 0, errors.New("empty or invalid cookieEncryptionKey in the configuration")
	}
	csk, ok := viper.Get(config.KeyInternalCookieSigningKey).(jwk.Key)
	if !ok || csk == nil {
		return "", 0, errors.New("empty or invalid cookie signing key in the configuration")
	}

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
		jwe.WithKey(jwa.A128KW, cek),
	)
	if err != nil {
		return "", 0, fmt.Errorf("failed to decrypt token in cookie: %w", err)
	}

	// Parse the encrypted JWT in the cookie
	token, err := jwt.Parse(dec,
		jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(viper.GetString(config.KeyAzureClientId)),
		jwt.WithKey(jwa.HS256, csk),
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
	cek, ok := viper.Get(config.KeyInternalCookieEncryptionKey).(jwk.Key)
	if !ok || cek == nil {
		return errors.New("empty or invalid cookieEncryptionKey in the configuration")
	}
	csk, ok := viper.Get(config.KeyInternalCookieSigningKey).(jwk.Key)
	if !ok || csk == nil {
		return errors.New("empty or invalid cookie signing key in the configuration")
	}

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{
			// Use the Azure client ID as our audience too
			viper.GetString(config.KeyAzureClientId),
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
		Sign(jwt.WithKey(jwa.HS256, csk)).
		Encrypt(
			jwt.WithKey(jwa.A128KW, cek),
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
