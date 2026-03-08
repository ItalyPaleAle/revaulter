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
	Username       string          `json:"username"`
	DisplayName    string          `json:"displayName"`
	ChallengeID    string          `json:"challengeId"`
	Credential     json.RawMessage `json:"credential"`
	PasswordFactor *struct {
		AuthKey string `json:"authKey"`
	} `json:"passwordFactor,omitempty"`
}

type v2AuthLoginBeginRequest struct {
	Username string `json:"username"`
}

type v2AuthLoginFinishRequest struct {
	Username      string          `json:"username"`
	ChallengeID   string          `json:"challengeId"`
	Credential    json.RawMessage `json:"credential"`
	PasswordProof string          `json:"passwordProof,omitempty"`
}

type v2RegisterChallengePayload struct {
	WebAuthnSession    *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
	PasswordRequired   bool                     `json:"passwordRequired,omitempty"`
	PasswordSalt       string                   `json:"passwordSalt,omitempty"`
	PasswordIterations int                      `json:"passwordIterations,omitempty"`
}

type v2LoginChallengePayload struct {
	Challenge              string                   `json:"challenge,omitempty"`
	WebAuthnSession        *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
	PasswordRequired       bool                     `json:"passwordRequired,omitempty"`
	PasswordSalt           string                   `json:"passwordSalt,omitempty"`
	PasswordIterations     int                      `json:"passwordIterations,omitempty"`
	PasswordProofChallenge string                   `json:"passwordProofChallenge,omitempty"`
}

func (s *Server) RouteV2AuthRegisterBegin(c *gin.Context) {
	s.routeV2AuthRegisterBegin(c, false)
}

func (s *Server) RouteV2AuthAdminRegisterBegin(c *gin.Context) {
	s.routeV2AuthRegisterBegin(c, true)
}

func (s *Server) routeV2AuthRegisterBegin(c *gin.Context, adminManaged bool) {
	if s.v2AuthStore == nil {
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

	count, err := s.v2AuthStore.CountAdmins(c.Request.Context())
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
	if existing, err := s.v2AuthStore.GetAdminByUsername(c.Request.Context(), req.Username); err != nil {
		AbortWithErrorJSON(c, err)
		return
	} else if existing != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Username already exists"))
		return
	}
	cfg := config.Get()
	pwRequired := cfg.PasswordFactorMode == "required"
	pwIterations := cfg.PasswordPBKDF2Iterations
	if pwIterations <= 0 {
		pwIterations = 300000
	}
	pwSalt := ""
	if pwRequired {
		pwSalt, err = randomB64URL(16)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
	}
	var ch *v2db.AuthChallenge
	challengeKind := "register"
	if adminManaged {
		challengeKind = "register-admin"
	}
	if s.v2WebAuthn != nil {
		user, err := newV2WebAuthnUserForRegistration(req.Username, req.DisplayName)
		if err == nil {
			creation, session, waErr := s.v2WebAuthn.BeginRegistration(user)
			if waErr == nil {
				ch, err = s.v2AuthStore.BeginChallengeWithPayload(c.Request.Context(), challengeKind, req.Username, session.Challenge, session.Expires, v2RegisterChallengePayload{
					WebAuthnSession:    session,
					PasswordRequired:   pwRequired,
					PasswordSalt:       pwSalt,
					PasswordIterations: pwIterations,
				})
				if err == nil {
					c.JSON(http.StatusOK, gin.H{
						"challengeId":              ch.ID,
						"challenge":                session.Challenge,
						"username":                 req.Username,
						"displayName":              req.DisplayName,
						"expiresAt":                ch.ExpiresAt.Unix(),
						"mode":                     "webauthn",
						"options":                  creation,
						"passwordFactorRequired":   pwRequired,
						"passwordSalt":             pwSalt,
						"passwordPbkdf2Iterations": pwIterations,
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
	ch, err = s.v2AuthStore.BeginChallengeWithPayload(c.Request.Context(), challengeKind, req.Username, fallbackChallenge, time.Now().Add(5*time.Minute), v2RegisterChallengePayload{
		PasswordRequired:   pwRequired,
		PasswordSalt:       pwSalt,
		PasswordIterations: pwIterations,
	})
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
		// Placeholder contract: browser can wrap a real WebAuthn payload into `credential`.
		"mode":                     "webauthn-placeholder",
		"passwordFactorRequired":   pwRequired,
		"passwordSalt":             pwSalt,
		"passwordPbkdf2Iterations": pwIterations,
	})
}

func (s *Server) RouteV2AuthRegisterFinish(c *gin.Context) {
	s.routeV2AuthRegisterFinish(c, false)
}

func (s *Server) RouteV2AuthAdminRegisterFinish(c *gin.Context) {
	s.routeV2AuthRegisterFinish(c, true)
}

func (s *Server) routeV2AuthRegisterFinish(c *gin.Context, adminManaged bool) {
	if s.v2AuthStore == nil {
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
			"username":         req.Username,
			"ttl":              int(time.Until(sess.ExpiresAt).Seconds()),
			"passwordVerified": sess.PasswordVerified,
		},
	})
}

func (s *Server) RouteV2AuthLoginBegin(c *gin.Context) {
	if s.v2AuthStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthLoginBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.Username = normalizeV2Username(req.Username)
	if req.Username == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "username is required"))
		return
	}

	admin, err := s.v2AuthStore.GetAdminByUsername(c.Request.Context(), req.Username)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if admin == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Invalid login"))
		return
	}
	credIDs, err := s.v2AuthStore.ListCredentialIDs(c.Request.Context(), req.Username)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	cfg := config.Get()
	pwRequired := cfg.PasswordFactorMode == "required"
	pwFactor, err := s.v2AuthStore.GetPasswordFactorByUsername(c.Request.Context(), req.Username)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if pwRequired && (pwFactor == nil || !pwFactor.Enabled) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Password factor is required for this account"))
		return
	}
	var pwSalt string
	var pwIterations int
	var pwProofChallenge string
	if pwFactor != nil && pwFactor.Enabled {
		pwSalt = pwFactor.Salt
		pwIterations = pwFactor.Iterations
		pwProofChallenge, err = randomB64URL(32)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
	}
	var ch *v2db.AuthChallenge
	var prfSalt string
	if s.v2WebAuthn != nil {
		user, uErr := s.v2LoadWebAuthnUser(c.Request.Context(), req.Username)
		if uErr == nil && user != nil {
			buf := make([]byte, 32)
			if _, rErr := rand.Read(buf); rErr == nil {
				prfSalt = base64.RawURLEncoding.EncodeToString(buf)
				assertion, session, waErr := s.v2WebAuthn.BeginLogin(user,
					webauthnlib.WithAssertionExtensions(protocol.AuthenticationExtensions{
						"prf": map[string]any{
							"eval": map[string]any{
								"first": buf,
							},
						},
					}),
				)
				if waErr == nil {
					ch, err = s.v2AuthStore.BeginChallengeWithPayload(c.Request.Context(), "login", req.Username, session.Challenge, session.Expires, v2LoginChallengePayload{
						Challenge:              session.Challenge,
						WebAuthnSession:        session,
						PasswordRequired:       pwRequired,
						PasswordSalt:           pwSalt,
						PasswordIterations:     pwIterations,
						PasswordProofChallenge: pwProofChallenge,
					})
					if err == nil {
						c.JSON(http.StatusOK, gin.H{
							"challengeId":              ch.ID,
							"challenge":                session.Challenge,
							"username":                 req.Username,
							"allowedCredentialIds":     credIDs,
							"expiresAt":                ch.ExpiresAt.Unix(),
							"mode":                     "webauthn",
							"options":                  assertion,
							"prfSalt":                  prfSalt,
							"passwordFactorRequired":   pwRequired,
							"passwordSalt":             pwSalt,
							"passwordPbkdf2Iterations": pwIterations,
							"passwordProofChallenge":   pwProofChallenge,
						})
						return
					}
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
	ch, err = s.v2AuthStore.BeginChallengeWithPayload(c.Request.Context(), "login", req.Username, fallbackChallenge, time.Now().Add(5*time.Minute), v2LoginChallengePayload{
		Challenge:              fallbackChallenge,
		PasswordRequired:       pwRequired,
		PasswordSalt:           pwSalt,
		PasswordIterations:     pwIterations,
		PasswordProofChallenge: pwProofChallenge,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challengeId":              ch.ID,
		"challenge":                ch.Challenge,
		"username":                 req.Username,
		"allowedCredentialIds":     credIDs,
		"expiresAt":                ch.ExpiresAt.Unix(),
		"mode":                     "webauthn-placeholder",
		"passwordFactorRequired":   pwRequired,
		"passwordSalt":             pwSalt,
		"passwordPbkdf2Iterations": pwIterations,
		"passwordProofChallenge":   pwProofChallenge,
	})
}

func (s *Server) RouteV2AuthLoginFinish(c *gin.Context) {
	if s.v2AuthStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	var req v2AuthLoginFinishRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.Username = normalizeV2Username(req.Username)
	if req.Username == "" || req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required login fields"))
		return
	}
	sess, err := s.v2LoginFinish(c, req)
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
			"username":         req.Username,
			"ttl":              int(time.Until(sess.ExpiresAt).Seconds()),
			"passwordVerified": sess.PasswordVerified,
		},
	})
}

func (s *Server) RouteV2AuthSession(c *gin.Context) {
	username, _ := c.Get(contextKeyV2AdminUsername)
	expiryAny, _ := c.Get(contextKeyV2SessionExpiry)
	expiry, _ := expiryAny.(time.Time)
	passwordVerifiedAny, _ := c.Get(contextKeyV2PasswordVerified)
	passwordVerified, _ := passwordVerifiedAny.(bool)
	if username == nil || expiry.IsZero() {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authenticated":    true,
		"username":         username,
		"ttl":              int(time.Until(expiry).Seconds()),
		"passwordVerified": passwordVerified,
	})
}

func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	if s.v2AuthStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "v2 auth is not configured"))
		return
	}
	sessID, _ := c.Get(contextKeyV2SessionID)
	if id, _ := sessID.(string); id != "" {
		_ = s.v2AuthStore.RevokeSession(c.Request.Context(), id)
	}
	secureCookie := config.Get().ForceSecureCookies || c.Request.URL.Scheme == "https:"
	c.SetCookie(v2SessionCookieName, "", -1, "/v2", c.Request.URL.Host, secureCookie, true)
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
	return setSecureCookie(c, v2SessionCookieName, sess.ID, ttl, "/v2", c.Request.URL.Host, secureCookie, true, serializeSecureCookieEncryptedJWT)
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

func buildV2PasswordProofMessage(username, challengeID, webauthnChallenge, passwordProofChallenge string) []byte {
	return []byte(strings.Join([]string{
		"revaulter-v2-password-proof",
		username,
		challengeID,
		webauthnChallenge,
		passwordProofChallenge,
	}, "|"))
}

func (s *Server) v2RegisterFinish(c *gin.Context, req v2AuthRegisterFinishRequest) (*v2db.AuthSession, error) {
	cfg := config.Get()
	pwRequired := cfg.PasswordFactorMode == "required"
	if s.v2WebAuthn == nil {
		if !s.v2AllowAuthPlaceholder {
			return nil, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
		}
		legacy, err := parseLegacyRegisterCredential(req.Credential)
		if err != nil {
			return nil, NewResponseError(http.StatusBadRequest, "Invalid registration credential payload")
		}
		var payload v2RegisterChallengePayload
		ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "register", req.Username, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
		}
		var pwEnrollment *v2db.PasswordFactorEnrollment
		if pwRequired {
			if req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "" {
				return nil, NewResponseError(http.StatusBadRequest, "Password factor is required")
			}
			pwEnrollment = &v2db.PasswordFactorEnrollment{
				Salt: payload.PasswordSalt,
				Iterations: func() int {
					if payload.PasswordIterations > 0 {
						return payload.PasswordIterations
					}
					return cfg.PasswordPBKDF2Iterations
				}(),
				AuthKey: req.PasswordFactor.AuthKey,
			}
		}
		return s.v2AuthStore.RegisterFirstAdmin(c.Request.Context(), v2db.RegisterFirstAdminInput{
			Username:       req.Username,
			DisplayName:    req.DisplayName,
			CredentialID:   legacy.ID,
			PublicKey:      legacy.PublicKey,
			SignCount:      legacy.SignCount,
			PasswordFactor: pwEnrollment,
			SessionTTL:     config.Get().SessionTimeout,
		})
	}

	var payload v2RegisterChallengePayload
	ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "register", req.Username, &payload)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}
	if payload.PasswordRequired && (req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "") {
		return nil, NewResponseError(http.StatusBadRequest, "Password factor is required")
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
	cred, err := s.v2WebAuthn.FinishRegistration(user, *payload.WebAuthnSession, waReq)
	if err != nil {
		return nil, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err)
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	sess, err := s.v2AuthStore.RegisterFirstAdmin(c.Request.Context(), v2db.RegisterFirstAdminInput{
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:    string(credJSON),
		SignCount:    int64(cred.Authenticator.SignCount),
		PasswordFactor: func() *v2db.PasswordFactorEnrollment {
			if !payload.PasswordRequired {
				return nil
			}
			if req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "" {
				return nil
			}
			return &v2db.PasswordFactorEnrollment{
				Salt: payload.PasswordSalt,
				Iterations: func() int {
					if payload.PasswordIterations > 0 {
						return payload.PasswordIterations
					}
					return cfg.PasswordPBKDF2Iterations
				}(),
				AuthKey: req.PasswordFactor.AuthKey,
			}
		}(),
		SessionTTL: config.Get().SessionTimeout,
	})
	if err == v2db.ErrFirstAdminAlreadyExists {
		return nil, NewResponseError(http.StatusConflict, "First admin already exists; use login")
	}
	return sess, err
}

func (s *Server) v2RegisterAdditionalAdminFinish(c *gin.Context, req v2AuthRegisterFinishRequest) error {
	cfg := config.Get()
	pwRequired := cfg.PasswordFactorMode == "required"
	challengeKind := "register-admin"
	if s.v2WebAuthn == nil {
		if !s.v2AllowAuthPlaceholder {
			return NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
		}
		legacy, err := parseLegacyRegisterCredential(req.Credential)
		if err != nil {
			return NewResponseError(http.StatusBadRequest, "Invalid registration credential payload")
		}
		var payload v2RegisterChallengePayload
		ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, challengeKind, req.Username, &payload)
		if err != nil {
			return err
		}
		if !ok {
			return NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
		}
		var pwEnrollment *v2db.PasswordFactorEnrollment
		if pwRequired {
			if req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "" {
				return NewResponseError(http.StatusBadRequest, "Password factor is required")
			}
			pwEnrollment = &v2db.PasswordFactorEnrollment{
				Salt: payload.PasswordSalt,
				Iterations: func() int {
					if payload.PasswordIterations > 0 {
						return payload.PasswordIterations
					}
					return cfg.PasswordPBKDF2Iterations
				}(),
				AuthKey: req.PasswordFactor.AuthKey,
			}
		}
		err = s.v2AuthStore.RegisterAdmin(c.Request.Context(), v2db.RegisterAdminInput{
			Username:       req.Username,
			DisplayName:    req.DisplayName,
			CredentialID:   legacy.ID,
			PublicKey:      legacy.PublicKey,
			SignCount:      legacy.SignCount,
			PasswordFactor: pwEnrollment,
		})
		if err == v2db.ErrAdminAlreadyExists {
			return NewResponseError(http.StatusConflict, "Username already exists")
		}
		return err
	}

	var payload v2RegisterChallengePayload
	ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, challengeKind, req.Username, &payload)
	if err != nil {
		return err
	}
	if !ok {
		return NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}
	if payload.PasswordRequired && (req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "") {
		return NewResponseError(http.StatusBadRequest, "Password factor is required")
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
	cred, err := s.v2WebAuthn.FinishRegistration(user, *payload.WebAuthnSession, waReq)
	if err != nil {
		return NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err)
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	err = s.v2AuthStore.RegisterAdmin(c.Request.Context(), v2db.RegisterAdminInput{
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:    string(credJSON),
		SignCount:    int64(cred.Authenticator.SignCount),
		PasswordFactor: func() *v2db.PasswordFactorEnrollment {
			if !payload.PasswordRequired {
				return nil
			}
			if req.PasswordFactor == nil || req.PasswordFactor.AuthKey == "" {
				return nil
			}
			return &v2db.PasswordFactorEnrollment{
				Salt: payload.PasswordSalt,
				Iterations: func() int {
					if payload.PasswordIterations > 0 {
						return payload.PasswordIterations
					}
					return cfg.PasswordPBKDF2Iterations
				}(),
				AuthKey: req.PasswordFactor.AuthKey,
			}
		}(),
	})
	if err == v2db.ErrAdminAlreadyExists {
		return NewResponseError(http.StatusConflict, "Username already exists")
	}
	return err
}

func (s *Server) v2LoginFinish(c *gin.Context, req v2AuthLoginFinishRequest) (*v2db.AuthSession, error) {
	cfg := config.Get()
	pwRequiredCfg := cfg.PasswordFactorMode == "required"
	if s.v2WebAuthn == nil {
		if !s.v2AllowAuthPlaceholder {
			return nil, NewResponseError(http.StatusServiceUnavailable, "WebAuthn is not available on this server")
		}
		legacy, err := parseLegacyLoginCredential(req.Credential)
		if err != nil {
			return nil, NewResponseError(http.StatusBadRequest, "Invalid login credential payload")
		}
		var payload v2LoginChallengePayload
		ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "login", req.Username, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
		}
		passwordVerified := false
		if payload.PasswordRequired || pwRequiredCfg {
			if req.PasswordProof == "" {
				return nil, NewResponseError(http.StatusUnauthorized, "Password factor proof is required")
			}
			pf, err := s.v2AuthStore.GetPasswordFactorByUsername(c.Request.Context(), req.Username)
			if err != nil {
				return nil, err
			}
			if pf == nil || !pf.Enabled {
				return nil, NewResponseError(http.StatusUnauthorized, "Password factor not enrolled")
			}
			challengeForProof := payload.Challenge
			if challengeForProof == "" && payload.WebAuthnSession != nil {
				challengeForProof = payload.WebAuthnSession.Challenge
			}
			msg := buildV2PasswordProofMessage(req.Username, req.ChallengeID, challengeForProof, payload.PasswordProofChallenge)
			if !v2db.VerifyPasswordProof(pf.AuthKey, req.PasswordProof, msg) {
				return nil, NewResponseError(http.StatusUnauthorized, "Invalid password factor proof")
			}
			passwordVerified = true
		}
		sess, err := s.v2AuthStore.Login(c.Request.Context(), v2db.LoginInput{
			Username:         req.Username,
			CredentialID:     legacy.ID,
			SignCount:        legacy.SignCount,
			PasswordVerified: passwordVerified,
			SessionTTL:       config.Get().SessionTimeout,
		})
		if err == v2db.ErrInvalidLogin {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}
		return sess, err
	}

	var payload v2LoginChallengePayload
	ok, err := s.v2AuthStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "login", req.Username, &payload)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	}
	if payload.WebAuthnSession == nil {
		return nil, NewResponseError(http.StatusConflict, "Login challenge is missing WebAuthn session data")
	}
	user, err := s.v2LoadWebAuthnUser(c.Request.Context(), req.Username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}
	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return nil, err
	}
	cred, err := s.v2WebAuthn.FinishLogin(user, *payload.WebAuthnSession, waReq)
	if err != nil {
		return nil, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn login verification failed: %v", err)
	}
	passwordVerified := false
	if payload.PasswordRequired {
		if req.PasswordProof == "" {
			return nil, NewResponseError(http.StatusUnauthorized, "Password factor proof is required")
		}
		pf, err := s.v2AuthStore.GetPasswordFactorByUsername(c.Request.Context(), req.Username)
		if err != nil {
			return nil, err
		}
		if pf == nil || !pf.Enabled {
			return nil, NewResponseError(http.StatusUnauthorized, "Password factor not enrolled")
		}
		challengeForProof := payload.Challenge
		if challengeForProof == "" {
			challengeForProof = payload.WebAuthnSession.Challenge
		}
		msg := buildV2PasswordProofMessage(req.Username, req.ChallengeID, challengeForProof, payload.PasswordProofChallenge)
		if !v2db.VerifyPasswordProof(pf.AuthKey, req.PasswordProof, msg) {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid password factor proof")
		}
		passwordVerified = true
	}
	sess, err := s.v2AuthStore.Login(c.Request.Context(), v2db.LoginInput{
		Username:         req.Username,
		CredentialID:     base64.RawURLEncoding.EncodeToString(cred.ID),
		SignCount:        int64(cred.Authenticator.SignCount),
		PasswordVerified: passwordVerified,
		SessionTTL:       config.Get().SessionTimeout,
	})
	if err == v2db.ErrInvalidLogin {
		return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}
	return sess, err
}

type v2LegacyRegisterCredential struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	SignCount int64  `json:"signCount"`
}

type v2LegacyLoginCredential struct {
	ID        string `json:"id"`
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

func parseLegacyLoginCredential(raw json.RawMessage) (*v2LegacyLoginCredential, error) {
	var v v2LegacyLoginCredential
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v.ID == "" {
		return nil, NewResponseError(http.StatusBadRequest, "Missing required login credential fields")
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
	admin, err := s.v2AuthStore.GetAdminByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if admin == nil || admin.Status != "active" {
		return nil, nil
	}
	records, err := s.v2AuthStore.ListCredentials(ctx, username)
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
	return &v2WebAuthnUser{
		id:          []byte(admin.ID),
		name:        admin.Username,
		displayName: admin.DisplayName,
		credentials: creds,
	}, nil
}
