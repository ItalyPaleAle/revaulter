package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/pkg/config"
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

func (s *Server) RouteV2AuthStatus(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	count, err := s.authStore.CountAdmins(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"setupNeeded": count == 0,
	})
}

func (s *Server) RouteV2AuthRegisterBegin(c *gin.Context) {
	s.routeV2AuthRegisterBegin(c, false)
}

func (s *Server) RouteV2AuthAdminRegisterBegin(c *gin.Context) {
	s.routeV2AuthRegisterBegin(c, true)
}

func (s *Server) routeV2AuthRegisterBegin(c *gin.Context, adminManaged bool) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthRegisterBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.Username = normalizeV2Username(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" || req.DisplayName == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "username and displayName are required"))
		return
	}

	count, err := s.authStore.CountAdmins(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if adminManaged {
		if count == 0 {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Register the first admin first"))
			return
		}
	} else {
		if count > 0 {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Registration is closed; use login"))
			return
		}
	}
	if existing, err := s.authStore.GetAdminByUsername(c.Request.Context(), req.Username); err != nil {
		AbortWithErrorJSON(c, err)
		return
	} else if existing != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Username already exists"))
		return
	}
	var ch *v2db.AuthChallenge
	challengeKind := "register"
	if adminManaged {
		challengeKind = "register-admin"
	}
	if s.webAuthn != nil {
		user, err := newV2WebAuthnUserForRegistration(req.Username, req.DisplayName)
		if err == nil {
			creation, session, waErr := s.webAuthn.BeginRegistration(user,
				webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
				webauthnlib.WithExtensions(protocol.AuthenticationExtensions{
					"prf": map[string]any{},
				}),
			)
			if waErr == nil {
				ch, err = s.authStore.BeginChallengeWithPayload(c.Request.Context(), challengeKind, req.Username, session.Challenge, session.Expires, v2RegisterChallengePayload{
					WebAuthnSession: session,
				})
				if err == nil {
					c.JSON(http.StatusOK, gin.H{
						"challengeId": ch.ID,
						"challenge":   session.Challenge,
						"username":    req.Username,
						"displayName": req.DisplayName,
						"expiresAt":   ch.ExpiresAt.Unix(),
						"mode":        "webauthn",
						"options":     creation,
					})
					return
				}
			}
		}
	}
	if !s.v2AllowAuthPlaceholder {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server"))
		return
	}
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	fallbackChallenge, err := randomB64URL(32)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	ch, err = s.authStore.BeginChallengeWithPayload(c.Request.Context(), challengeKind, req.Username, fallbackChallenge, time.Now().Add(5*time.Minute), v2RegisterChallengePayload{})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challengeId": ch.ID,
		"challenge":   ch.Challenge,
		"username":    req.Username,
		"displayName": req.DisplayName,
		"expiresAt":   ch.ExpiresAt.Unix(),
		// Placeholder contract: browser can wrap a real WebAuthn payload into `credential`
		"mode": "webauthn-placeholder",
	})
}

func (s *Server) RouteV2AuthRegisterFinish(c *gin.Context) {
	s.routeV2AuthRegisterFinish(c, false)
}

func (s *Server) RouteV2AuthAdminRegisterFinish(c *gin.Context) {
	s.routeV2AuthRegisterFinish(c, true)
}

func (s *Server) routeV2AuthRegisterFinish(c *gin.Context, adminManaged bool) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthRegisterFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.Username = normalizeV2Username(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" || req.DisplayName == "" || req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required registration fields"))
		return
	}
	if adminManaged {
		if err := s.v2RegisterAdditionalAdminFinish(c, req); err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"registered": true,
			"username":   req.Username,
		})
		return
	}
	sess, err := s.v2RegisterFinish(c, req)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if err := s.setV2SessionCookie(c, sess); err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"registered": true,
		"session": gin.H{
			"username": req.Username,
			"ttl":      int(time.Until(sess.ExpiresAt).Seconds()),
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

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	prfSalt := base64.RawURLEncoding.EncodeToString(buf)

	assertion, session, err := s.webAuthn.BeginDiscoverableLogin(
		webauthnlib.WithAssertionExtensions(protocol.AuthenticationExtensions{
			"prf": map[string]any{
				"eval": map[string]any{
					"first": buf,
				},
			},
		}),
	)
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

	c.JSON(http.StatusOK, gin.H{
		"challengeId": ch.ID,
		"challenge":   session.Challenge,
		"expiresAt":   ch.ExpiresAt.Unix(),
		"mode":        "webauthn",
		"options":     assertion,
		"prfSalt":     prfSalt,
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
		AbortWithErrorJSON(c, err)
		return
	}
	if err := s.setV2SessionCookie(c, sess); err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"session": gin.H{
			"username": username,
			"ttl":      int(time.Until(sess.ExpiresAt).Seconds()),
		},
	})
}

func (s *Server) RouteV2AuthSession(c *gin.Context) {
	username, _ := c.Get(contextKeyAdminUsername)
	expiryAny, _ := c.Get(contextKeySessionExpiry)
	expiry, _ := expiryAny.(time.Time)
	if username == nil || expiry.IsZero() {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"username":      username,
		"ttl":           int(time.Until(expiry).Seconds()),
	})
}

func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	if s.authStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	sessID, _ := c.Get(contextKeySessionID)
	if id, _ := sessID.(string); id != "" {
		_ = s.authStore.RevokeSession(c.Request.Context(), id)
	}
	secureCookie := config.Get().ForceSecureCookies || c.Request.URL.Scheme == "https:"
	c.SetCookie(sessionCookieName, "", -1, "/v2", c.Request.URL.Host, secureCookie, true)
	c.JSON(http.StatusOK, gin.H{"loggedOut": true})
}

func (s *Server) setV2SessionCookie(c *gin.Context, sess *v2db.AuthSession) error {
	if sess == nil {
		return NewResponseError(http.StatusInternalServerError, "session is nil")
	}
	ttl := time.Until(sess.ExpiresAt)
	if ttl < time.Second {
		ttl = time.Second
	}
	secureCookie := config.Get().ForceSecureCookies || c.Request.URL.Scheme == "https:"
	return setSecureCookie(c, sessionCookieName, sess.ID, ttl, "/v2", c.Request.URL.Host, secureCookie, true, serializeSecureCookieEncryptedJWT)
}

func normalizeV2Username(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

func randomB64URL(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) v2RegisterFinish(c *gin.Context, req v2AuthRegisterFinishRequest) (*v2db.AuthSession, error) {
	if s.webAuthn == nil {
		if !s.v2AllowAuthPlaceholder {
			return nil, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
		}
		legacy, err := parseLegacyRegisterCredential(req.Credential)
		if err != nil {
			return nil, NewResponseError(http.StatusBadRequest, "Invalid registration credential payload")
		}
		var payload v2RegisterChallengePayload
		ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "register", req.Username, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
		}
		webAuthnUserID := ""
		if payload.WebAuthnSession != nil {
			webAuthnUserID = base64.RawURLEncoding.EncodeToString(payload.WebAuthnSession.UserID)
		}
		return s.authStore.RegisterFirstAdmin(c.Request.Context(), v2db.RegisterFirstAdminInput{
			Username:       req.Username,
			DisplayName:    req.DisplayName,
			WebAuthnUserID: webAuthnUserID,
			CredentialID:   legacy.ID,
			PublicKey:      legacy.PublicKey,
			SignCount:      legacy.SignCount,
			SessionTTL:     config.Get().SessionTimeout,
		})
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
	sess, err := s.authStore.RegisterFirstAdmin(c.Request.Context(), v2db.RegisterFirstAdminInput{
		Username:       req.Username,
		DisplayName:    req.DisplayName,
		WebAuthnUserID: base64.RawURLEncoding.EncodeToString(payload.WebAuthnSession.UserID),
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      string(credJSON),
		SignCount:      int64(cred.Authenticator.SignCount),
		SessionTTL:     config.Get().SessionTimeout,
	})
	if err == v2db.ErrFirstAdminAlreadyExists {
		return nil, NewResponseError(http.StatusConflict, "First admin already exists; use login")
	}
	return sess, err
}

func (s *Server) v2RegisterAdditionalAdminFinish(c *gin.Context, req v2AuthRegisterFinishRequest) error {
	challengeKind := "register-admin"
	if s.webAuthn == nil {
		if !s.v2AllowAuthPlaceholder {
			return NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
		}
		legacy, err := parseLegacyRegisterCredential(req.Credential)
		if err != nil {
			return NewResponseError(http.StatusBadRequest, "Invalid registration credential payload")
		}
		var payload v2RegisterChallengePayload
		ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, challengeKind, req.Username, &payload)
		if err != nil {
			return err
		}
		if !ok {
			return NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
		}
		webAuthnUserID := ""
		if payload.WebAuthnSession != nil {
			webAuthnUserID = base64.RawURLEncoding.EncodeToString(payload.WebAuthnSession.UserID)
		}
		err = s.authStore.RegisterAdmin(c.Request.Context(), v2db.RegisterAdminInput{
			Username:       req.Username,
			DisplayName:    req.DisplayName,
			WebAuthnUserID: webAuthnUserID,
			CredentialID:   legacy.ID,
			PublicKey:      legacy.PublicKey,
			SignCount:      legacy.SignCount,
		})
		if err == v2db.ErrAdminAlreadyExists {
			return NewResponseError(http.StatusConflict, "Username already exists")
		}
		return err
	}

	var payload v2RegisterChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, challengeKind, req.Username, &payload)
	if err != nil {
		return err
	}
	if !ok {
		return NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}
	user := &v2WebAuthnUser{
		id:          payload.WebAuthnSession.UserID,
		name:        req.Username,
		displayName: req.DisplayName,
	}
	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return err
	}
	cred, err := s.webAuthn.FinishRegistration(user, *payload.WebAuthnSession, waReq)
	if err != nil {
		return NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err)
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	err = s.authStore.RegisterAdmin(c.Request.Context(), v2db.RegisterAdminInput{
		Username:       req.Username,
		DisplayName:    req.DisplayName,
		WebAuthnUserID: base64.RawURLEncoding.EncodeToString(payload.WebAuthnSession.UserID),
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      string(credJSON),
		SignCount:      int64(cred.Authenticator.SignCount),
	})
	if err == v2db.ErrAdminAlreadyExists {
		return NewResponseError(http.StatusConflict, "Username already exists")
	}
	return err
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

	// FinishDiscoverableLogin identifies the user from the credential's userHandle.
	var discoveredUser *v2WebAuthnUser
	handler := func(rawID, userHandle []byte) (webauthnlib.User, error) {
		webAuthnUserID := base64.RawURLEncoding.EncodeToString(userHandle)
		admin, err := s.authStore.GetAdminByWebAuthnUserID(c.Request.Context(), webAuthnUserID)
		if err != nil {
			return nil, err
		}
		if admin == nil || admin.Status != "active" {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}
		user, err := s.v2LoadWebAuthnUser(c.Request.Context(), admin.Username)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}
		discoveredUser = user
		return user, nil
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

	sess, err := s.authStore.Login(c.Request.Context(), v2db.LoginInput{
		Username:     username,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		SignCount:    int64(cred.Authenticator.SignCount),
		SessionTTL:   config.Get().SessionTimeout,
	})
	if err == v2db.ErrInvalidLogin {
		return nil, "", NewResponseError(http.StatusUnauthorized, "Invalid login")
	}
	return sess, username, err
}

type v2LegacyRegisterCredential struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	SignCount int64  `json:"signCount"`
}

func parseLegacyRegisterCredential(raw json.RawMessage) (*v2LegacyRegisterCredential, error) {
	var v v2LegacyRegisterCredential
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v.ID == "" || v.PublicKey == "" {
		return nil, NewResponseError(http.StatusBadRequest, "Missing required registration credential fields")
	}
	return &v, nil
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
	admin, err := s.authStore.GetAdminByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if admin == nil || admin.Status != "active" {
		return nil, nil
	}
	records, err := s.authStore.ListCredentials(ctx, username)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthnlib.Credential, 0, len(records))
	for _, rec := range records {
		var c webauthnlib.Credential
		if err := json.Unmarshal([]byte(rec.PublicKey), &c); err != nil {
			// Skip placeholder credentials created before WebAuthn verification support.
			continue
		}
		c.Authenticator.SignCount = uint32(rec.SignCount)
		creds = append(creds, c)
	}
	if len(creds) == 0 {
		return nil, nil
	}
	// Use the stored WebAuthn user ID if available; fall back to the DB admin ID for pre-migration admins.
	userID := []byte(admin.ID)
	if admin.WebAuthnUserID != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(admin.WebAuthnUserID); err == nil {
			userID = decoded
		}
	}
	return &v2WebAuthnUser{
		id:          userID,
		name:        admin.Username,
		displayName: admin.DisplayName,
		credentials: creds,
	}, nil
}
