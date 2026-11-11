package server

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/italypaleale/revaulter/internal/actors"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

const (
	sessionClaimUserID      = "userId"
	sessionClaimDisplayName = "displayName"
	sessionClaimReady       = "ready"
	sessionClaimSignupID    = "signupId"

	// sessionClockSkew is the tolerance applied when validating session tokens' timestamps
	sessionClockSkew = 2 * time.Minute
)

type authSessionToken struct {
	UserID      string
	DisplayName string
	Ready       bool
	ExpiresAt   time.Time
	// ID of the signup, for users that haven't finalized their signup yet
	// These users aren't in the database until then, and the revaulter.signup actor with this ID holds their registration
	SignupID string
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

// newSignupSessionToken returns a session token for a user that hasn't finalized their signup yet
func newSignupSessionToken(signup *actors.Signup, ttl time.Duration) *authSessionToken {
	if ttl <= 0 {
		ttl = time.Minute
	}

	return &authSessionToken{
		UserID:      signup.UserID,
		DisplayName: signup.DisplayName,
		Ready:       false,
		SignupID:    signup.WebAuthnUserID,
		ExpiresAt:   time.Now().UTC().Add(ttl),
	}
}

func signAuthSessionToken(sess *authSessionToken) (string, error) {
	builder := jwt.NewBuilder().
		Subject(sess.UserID).
		IssuedAt(time.Now().UTC()).
		Expiration(sess.ExpiresAt).
		Claim(sessionClaimUserID, sess.UserID).
		Claim(sessionClaimDisplayName, sess.DisplayName).
		Claim(sessionClaimReady, sess.Ready)
	if sess.SignupID != "" {
		builder = builder.Claim(sessionClaimSignupID, sess.SignupID)
	}
	tok, err := builder.Build()
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

	// The signup ID is set only for users that haven't finalized their signup yet
	var signupID string
	if parsed.Has(sessionClaimSignupID) {
		signupID, err = jwt.Get[string](parsed, sessionClaimSignupID)
		if err != nil {
			return nil, err
		}
	}

	expiresAt, ok := parsed.Expiration()
	if !ok {
		return nil, errors.New("session token missing expiration")
	}

	return &authSessionToken{
		UserID:      userID,
		DisplayName: displayName,
		Ready:       ready,
		SignupID:    signupID,
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *Server) setSessionCookie(c *gin.Context, sess *authSessionToken) error {
	if sess == nil {
		return errors.New("session is nil")
	}

	ttl := max(time.Until(sess.ExpiresAt), time.Second)
	token, err := signAuthSessionToken(sess)
	if err != nil {
		return err
	}

	cookieName, cookiePath := s.sessionCookieFor(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, token, int(ttl.Seconds()), cookiePath, "", s.secureCookie(c), true)

	return nil
}

func sessionInfoFromUser(user *db.User, ttl int) *v2AuthSessionInfo {
	allowedIPs := user.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}

	requestOIDC := user.RequestOIDC
	if requestOIDC == nil {
		requestOIDC = []db.RequestOIDCIssuer{}
	}

	return &v2AuthSessionInfo{
		UserID:             user.ID,
		DisplayName:        user.DisplayName,
		RequestKey:         user.RequestKey,
		RequestKeyEnabled:  user.RequestAuthMethods.RequestKey,
		RequestOIDCEnabled: user.RequestAuthMethods.OIDC,
		RequestOIDCIssuers: requestOIDC,
		AnchorFingerprint:  computeAnchorFingerprint(user),
		WrappedKeyEpoch:    user.WrappedKeyEpoch,
		AllowedIPs:         allowedIPs,
		TTL:                max(ttl, 0),
	}
}

// sessionInfoFromSignup returns the session info for a user that hasn't finalized their signup yet
// The user has no request key, transport keys or anchor until the signup is finalized
func sessionInfoFromSignup(signup *actors.Signup, ttl int) *v2AuthSessionInfo {
	return &v2AuthSessionInfo{
		UserID:             signup.UserID,
		DisplayName:        signup.DisplayName,
		RequestKeyEnabled:  true,
		RequestOIDCIssuers: []db.RequestOIDCIssuer{},
		WrappedKeyEpoch:    1,
		AllowedIPs:         []string{},
		TTL:                max(ttl, 0),
	}
}

// computeAnchorFingerprint derives the TOFU anchor fingerprint from a user's stored anchor pubkeys
// Returns an empty string when the user hasn't set up anchor keys yet
func computeAnchorFingerprint(user *db.User) string {
	if user.AnchorEs384PublicKey == "" || user.AnchorMldsa87PublicKey == "" {
		return ""
	}

	jwk, err := protocolv2.ParseECP384PublicJWKCanonicalBody(user.AnchorEs384PublicKey)
	if err != nil {
		slog.Warn("Failed to parse anchor ES384 JWK for fingerprint",
			slog.String("user_id", user.ID),
			slog.Any("error", err),
		)
		return ""
	}

	ecdsaPub, err := jwk.ToECDSAPublicKey()
	if err != nil {
		return ""
	}

	mldsa87PubBytes, err := base64.RawURLEncoding.DecodeString(user.AnchorMldsa87PublicKey)
	if err != nil || len(mldsa87PubBytes) != protocolv2.MLDSA87PublicKeySize {
		return ""
	}

	fp, err := protocolv2.AnchorFingerprint(ecdsaPub, mldsa87PubBytes)
	if err != nil {
		return ""
	}

	return fp
}
