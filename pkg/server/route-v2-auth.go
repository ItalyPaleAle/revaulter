package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	location "github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/v2db"
)

type v2AuthRegisterBeginRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

type v2AuthRegisterFinishRequest struct {
	Username    string          `json:"username"`
	DisplayName string          `json:"displayName"`
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

type v2AuthLoginFinishRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

type v2RegisterChallengePayload struct {
	WebAuthnSession *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
}

type v2LoginChallengePayload struct {
	Challenge       string                   `json:"challenge,omitempty"`
	WebAuthnSession *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
}

type v2AuthRegisterBeginResponse struct {
	ChallengeID string `json:"challengeId"`
	Challenge   string `json:"challenge"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	ExpiresAt   int64  `json:"expiresAt"`
	Mode        string `json:"mode"`
	Options     any    `json:"options,omitempty"`
	BasePrfSalt string `json:"basePrfSalt"`
}

type v2AuthSessionInfo struct {
	Username string `json:"username"`
	TTL      int    `json:"ttl"`
}

type v2AuthRegisterFinishResponse struct {
	Registered bool               `json:"registered"`
	Username   string             `json:"username,omitempty"`
	Session    *v2AuthSessionInfo `json:"session,omitempty"`
}

type v2AuthLoginBeginResponse struct {
	ChallengeID string `json:"challengeId"`
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expiresAt"`
	Mode        string `json:"mode"`
	Options     any    `json:"options,omitempty"`
	BasePrfSalt string `json:"basePrfSalt"`
}

type v2AuthLoginFinishResponse struct {
	Authenticated  bool               `json:"authenticated"`
	Session        *v2AuthSessionInfo `json:"session,omitempty"`
	PasswordCanary string             `json:"passwordCanary,omitempty"`
}

type v2AuthSetPasswordCanaryRequest struct {
	Canary string `json:"canary"`
}

type v2AuthSessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username"`
	TTL           int    `json:"ttl"`
}

type v2AuthLogoutResponse struct {
	LoggedOut bool `json:"loggedOut"`
}

func (s *Server) RouteV2AuthRegisterBegin(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthRegisterBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.Username = normalizeUsername(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" || req.DisplayName == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "username and displayName are required"))
		return
	}
	if config.Get().DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}
	if existing, err := s.authStore.GetUserByUsername(c.Request.Context(), req.Username); err != nil {
		AbortWithErrorJSON(c, err)
		return
	} else if existing != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Username already exists"))
		return
	}
	if s.webAuthn == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server"))
		return
	}

	user, err := newV2WebAuthnUserForRegistration(req.Username, req.DisplayName)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	creation, session, err := s.webAuthn.BeginRegistration(user,
		webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthnlib.WithExtensions(protocol.AuthenticationExtensions{
			"prf": map[string]any{},
		}),
	)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	ch, err := s.authStore.BeginChallengeWithPayload(c.Request.Context(), "register", req.Username, session.Challenge, session.Expires, v2RegisterChallengePayload{
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, v2AuthRegisterBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		Username:    req.Username,
		DisplayName: req.DisplayName,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Mode:        "webauthn",
		Options:     creation,
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

func (s *Server) RouteV2AuthRegisterFinish(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}

	var req v2AuthRegisterFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	req.Username = normalizeUsername(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Username == "" || req.DisplayName == "" || req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required registration fields"))
		return
	}

	if config.Get().DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	sess, err := s.v2RegisterFinish(c, req)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "User registration failed",
			slog.String("username", req.Username),
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User registered",
		slog.String("username", req.Username),
		slog.String("client_ip", c.ClientIP()),
	)

	err = s.setV2SessionCookie(c, sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthRegisterFinishResponse{
		Registered: true,
		Session: &v2AuthSessionInfo{
			Username: req.Username,
			TTL:      int(time.Until(sess.ExpiresAt).Seconds()),
		},
	})
}

func (s *Server) RouteV2AuthLoginBegin(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	if s.webAuthn == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server"))
		return
	}

	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Store the challenge with an empty username — the user will be identified from the credential in finish.
	ch, err := s.authStore.BeginChallengeWithPayload(c.Request.Context(), "login", "", session.Challenge, session.Expires, v2LoginChallengePayload{
		Challenge:       session.Challenge,
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthLoginBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Mode:        "webauthn",
		Options:     assertion,
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

func (s *Server) RouteV2AuthLoginFinish(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthLoginFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required login fields"))
		return
	}
	sess, username, err := s.v2LoginFinish(c, req)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Login failed",
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged in",
		slog.String("username", username),
		slog.String("client_ip", c.ClientIP()),
	)

	if err := s.setV2SessionCookie(c, sess); err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	resp := v2AuthLoginFinishResponse{
		Authenticated: true,
		Session: &v2AuthSessionInfo{
			Username: username,
			TTL:      int(time.Until(sess.ExpiresAt).Seconds()),
		},
	}

	user, _ := s.authStore.GetUserByUsername(c.Request.Context(), username)
	if user != nil && user.PasswordCanary != "" {
		resp.PasswordCanary = user.PasswordCanary
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) RouteV2AuthSetPasswordCanary(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	username, _ := c.Get(contextKeyUsername)
	usernameStr, _ := username.(string)
	if usernameStr == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthSetPasswordCanaryRequest
	err := c.ShouldBindJSON(&req)
	if err != nil || req.Canary == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "canary is required"))
		return
	}
	if len(req.Canary) > 512 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "canary is too large"))
		return
	}

	err = s.authStore.SetPasswordCanary(c.Request.Context(), usernameStr, req.Canary)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

func (s *Server) RouteV2AuthSession(c *gin.Context) {
	username, _ := c.Get(contextKeyUsername)
	expiryAny, _ := c.Get(contextKeySessionExpiry)
	expiry, _ := expiryAny.(time.Time)
	if username == nil || expiry.IsZero() {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	c.JSON(http.StatusOK, v2AuthSessionResponse{
		Authenticated: true,
		Username:      username.(string),
		TTL:           int(time.Until(expiry).Seconds()),
	})
}

func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}

	username, _ := c.Get(contextKeyUsername)
	usernameStr, _ := username.(string)

	sessID, _ := c.Get(contextKeySessionID)
	id, _ := sessID.(string)
	if id != "" {
		err := s.authStore.RevokeSession(c.Request.Context(), id)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusInternalServerError, "Failed to revoke session"))
			return
		}
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged out",
		slog.String("username", usernameStr),
		slog.String("client_ip", c.ClientIP()),
	)

	cookieName, cookiePath := sessionCookieFor(c)
	isSecure := secureCookie(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, cookiePath, "", isSecure, true)
	// Also clear the old insecure cookie name in case it still exists
	if cookieName == sessionCookieNameSecure {
		c.SetCookie(sessionCookieNameInsecure, "", -1, "/v2", "", isSecure, true)
	}

	c.JSON(http.StatusOK, v2AuthLogoutResponse{LoggedOut: true})
}

func (s *Server) setV2SessionCookie(c *gin.Context, sess *v2db.AuthSession) error {
	if sess == nil {
		return NewResponseError(http.StatusInternalServerError, "session is nil")
	}

	ttl := time.Until(sess.ExpiresAt)
	if ttl < time.Second {
		ttl = time.Second
	}

	cookieName, cookiePath := sessionCookieFor(c)
	c.SetSameSite(http.SameSiteLaxMode)
	return setSecureCookie(c, cookieName, sess.ID, ttl, cookiePath, secureCookie(c), true, serializeSecureCookieEncryptedJWT)
}

func secureCookie(c *gin.Context) bool {
	url := location.Get(c)
	return url.Scheme == "https" || config.Get().ForceSecureCookies
}

func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

func (s *Server) v2RegisterFinish(c *gin.Context, req v2AuthRegisterFinishRequest) (*v2db.AuthSession, error) {
	if s.webAuthn == nil {
		return nil, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
	}

	var payload v2RegisterChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "register", req.Username, &payload)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}
	user := &v2WebAuthnUser{
		id:          payload.WebAuthnSession.UserID,
		name:        req.Username,
		displayName: req.DisplayName,
		credentials: nil,
	}
	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return nil, err
	}
	cred, err := s.webAuthn.FinishRegistration(user, *payload.WebAuthnSession, waReq)
	if err != nil {
		return nil, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err)
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	sess, err := s.authStore.RegisterUser(c.Request.Context(), v2db.RegisterUserInput{
		Username:       req.Username,
		DisplayName:    req.DisplayName,
		WebAuthnUserID: base64.RawURLEncoding.EncodeToString(payload.WebAuthnSession.UserID),
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      string(credJSON),
		SignCount:      int64(cred.Authenticator.SignCount),
		SessionTTL:     config.Get().SessionTimeout,
	})

	if errors.Is(err, v2db.ErrUserAlreadyExists) {
		return nil, NewResponseError(http.StatusConflict, "Username already exists")
	}

	return sess, err
}

func (s *Server) v2LoginFinish(c *gin.Context, req v2AuthLoginFinishRequest) (*v2db.AuthSession, string, error) {
	if s.webAuthn == nil {
		return nil, "", NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
	}

	var payload v2LoginChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "login", "", &payload)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, "", NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return nil, "", NewResponseError(http.StatusConflict, "Login challenge is missing WebAuthn session data")
	}

	// FinishDiscoverableLogin identifies the user from the credential's userHandle
	var discoveredUser *v2WebAuthnUser
	handler := func(rawID, userHandle []byte) (webauthnlib.User, error) {
		webAuthnUserID := base64.RawURLEncoding.EncodeToString(userHandle)
		user, err := s.authStore.GetUserByWebAuthnUserID(c.Request.Context(), webAuthnUserID)
		if err != nil {
			return nil, err
		}
		if user == nil || user.Status != "active" {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}

		userRecord, err := s.v2LoadWebAuthnUser(c.Request.Context(), user.Username)
		if err != nil {
			return nil, err
		}
		if userRecord == nil {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}

		discoveredUser = userRecord
		return userRecord, nil
	}

	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return nil, "", err
	}

	cred, err := s.webAuthn.FinishDiscoverableLogin(handler, *payload.WebAuthnSession, waReq)
	if err != nil {
		return nil, "", NewResponseErrorf(http.StatusUnauthorized, "WebAuthn login verification failed: %v", err)
	}

	if discoveredUser == nil {
		return nil, "", NewResponseError(http.StatusUnauthorized, "Invalid login")
	}
	username := discoveredUser.name

	// Detect possible cloned authenticator by comparing the returned sign count
	// with the stored value. If the stored count was non-zero but the new count
	// is not strictly greater, the credential may have been cloned.
	credIDEncoded := base64.RawURLEncoding.EncodeToString(cred.ID)
	for _, stored := range discoveredUser.credentials {
		if base64.RawURLEncoding.EncodeToString(stored.ID) == credIDEncoded {
			storedCount := stored.Authenticator.SignCount
			newCount := cred.Authenticator.SignCount
			if storedCount > 0 && newCount <= storedCount {
				logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
					"Possible cloned authenticator: sign count did not increase",
					slog.String("username", username),
					slog.String("credential_id", credIDEncoded),
					slog.Uint64("stored_sign_count", uint64(storedCount)),
					slog.Uint64("new_sign_count", uint64(newCount)),
					slog.String("client_ip", c.ClientIP()),
				)
				return nil, "", NewResponseError(http.StatusForbidden, "Authenticator sign count anomaly detected — possible credential cloning")
			}
			break
		}
	}

	sess, err := s.authStore.Login(c.Request.Context(), v2db.LoginInput{
		Username:     username,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		SignCount:    int64(cred.Authenticator.SignCount),
		SessionTTL:   config.Get().SessionTimeout,
	})

	if errors.Is(err, v2db.ErrInvalidLogin) {
		return nil, "", NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	return sess, username, err
}

func newJSONHTTPRequest(c *gin.Context, raw json.RawMessage) (*http.Request, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, NewResponseError(http.StatusBadRequest, "credential payload must be valid JSON")
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, c.Request.URL.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header = make(http.Header)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

type v2WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthnlib.Credential
}

func newV2WebAuthnUserForRegistration(username, displayName string) (*v2WebAuthnUser, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &v2WebAuthnUser{
		id:          id,
		name:        username,
		displayName: displayName,
	}, nil
}

func (u *v2WebAuthnUser) WebAuthnID() []byte                            { return u.id }
func (u *v2WebAuthnUser) WebAuthnName() string                          { return u.name }
func (u *v2WebAuthnUser) WebAuthnDisplayName() string                   { return u.displayName }
func (u *v2WebAuthnUser) WebAuthnCredentials() []webauthnlib.Credential { return u.credentials }

func (s *Server) v2LoadWebAuthnUser(ctx context.Context, username string) (*v2WebAuthnUser, error) {
	user, err := s.authStore.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, nil
	}
	records, err := s.authStore.ListCredentials(ctx, username)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthnlib.Credential, 0, len(records))
	for _, rec := range records {
		var c webauthnlib.Credential
		err = json.Unmarshal([]byte(rec.PublicKey), &c)
		if err != nil {
			// Skip legacy credential records that do not contain a verified WebAuthn credential
			continue
		}
		c.Authenticator.SignCount = uint32(rec.SignCount)
		creds = append(creds, c)
	}

	if len(creds) == 0 {
		return nil, nil
	}

	// Use the stored WebAuthn user ID if available; fall back to the DB row ID for pre-migration users.
	userID := []byte(user.ID)
	if user.WebAuthnUserID != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(user.WebAuthnUserID)
		if err == nil {
			userID = decoded
		}
	}

	return &v2WebAuthnUser{
		id:          userID,
		name:        user.Username,
		displayName: user.DisplayName,
		credentials: creds,
	}, nil
}
