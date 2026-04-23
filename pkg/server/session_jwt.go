package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
)

const (
	sessionClaimUserID      = "userId"
	sessionClaimDisplayName = "displayName"
	sessionClaimReady       = "ready"

	// sessionClockSkew is the tolerance applied when validating `iat`/`nbf`/`exp`
	sessionClockSkew = 2 * time.Minute
)

type authSessionToken struct {
	UserID      string
	DisplayName string
	Ready       bool
	ExpiresAt   time.Time
}

func newAuthSessionToken(user *db.User, ttl time.Duration) (*authSessionToken, error) {
	if ttl <= 0 {
		ttl = time.Minute
	}

	return &authSessionToken{
		UserID:      user.ID,
		DisplayName: user.DisplayName,
		Ready:       user.Ready,
		ExpiresAt:   time.Now().UTC().Add(ttl),
	}, nil
}

func signAuthSessionToken(sess *authSessionToken) (string, error) {
	tok, err := jwt.NewBuilder().
		Subject(sess.UserID).
		IssuedAt(time.Now().UTC()).
		Expiration(sess.ExpiresAt).
		Claim(sessionClaimUserID, sess.UserID).
		Claim(sessionClaimDisplayName, sess.DisplayName).
		Claim(sessionClaimReady, sess.Ready).
		Build()
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), config.Get().TokenSigningKey()))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func parseAuthSessionToken(token string) (*authSessionToken, error) {
	parsed, err := jwt.ParseString(token,
		jwt.WithKey(jwa.HS256(), config.Get().TokenSigningKey()),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(sessionClockSkew),
	)
	if err != nil {
		return nil, err
	}

	userID, err := jwt.Get[string](parsed, sessionClaimUserID)
	if err != nil {
		return nil, err
	}

	displayName, err := jwt.Get[string](parsed, sessionClaimDisplayName)
	if err != nil {
		return nil, err
	}

	ready, err := jwt.Get[bool](parsed, sessionClaimReady)
	if err != nil {
		return nil, err
	}

	expiresAt, ok := parsed.Expiration()
	if !ok {
		return nil, errors.New("session token missing expiration")
	}

	return &authSessionToken{
		UserID:      userID,
		DisplayName: displayName,
		Ready:       ready,
		ExpiresAt:   expiresAt,
	}, nil
}

func setSessionCookie(c *gin.Context, sess *authSessionToken) error {
	if sess == nil {
		return NewResponseError(http.StatusInternalServerError, "session is nil")
	}

	ttl := max(time.Until(sess.ExpiresAt), time.Second)
	token, err := signAuthSessionToken(sess)
	if err != nil {
		return err
	}

	cookieName, cookiePath := sessionCookieFor(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, token, int(ttl.Seconds()), cookiePath, "", secureCookie(c), true)

	return nil
}

func sessionInfoFromUser(user *db.User, ttl int) *v2AuthSessionInfo {
	if user == nil {
		return nil
	}

	allowedIPs := user.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}

	return &v2AuthSessionInfo{
		UserID:          user.ID,
		DisplayName:     user.DisplayName,
		RequestKey:      user.RequestKey,
		WrappedKeyEpoch: user.WrappedKeyEpoch,
		AllowedIPs:      allowedIPs,
		TTL:             max(ttl, 0),
	}
}
