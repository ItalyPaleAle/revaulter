package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	location "github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/italypaleale/go-kit/eventqueue"
	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

type v2AuthRegisterBeginRequest struct {
	DisplayName string `json:"displayName"`
}

type v2AuthRegisterFinishRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

type v2AuthLoginFinishRequest struct {
	ChallengeID string          `json:"challengeId"`
	Credential  json.RawMessage `json:"credential"`
}

type v2RegisterChallengePayload struct {
	UserID          string                   `json:"userId"`
	DisplayName     string                   `json:"displayName"`
	WebAuthnUserID  string                   `json:"webauthnUserId"`
	WebAuthnSession *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
}

type v2LoginChallengePayload struct {
	Challenge       string                   `json:"challenge,omitempty"`
	WebAuthnSession *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
}

type v2AuthRegisterBeginResponse struct {
	ChallengeID string `json:"challengeId"`
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expiresAt"`
	Mode        string `json:"mode"`
	Options     any    `json:"options,omitempty"`
	BasePrfSalt string `json:"basePrfSalt"`
}

type v2AuthSessionInfo struct {
	UserID      string   `json:"userId"`
	DisplayName string   `json:"displayName"`
	RequestKey  string   `json:"requestKey"`
	AllowedIPs  []string `json:"allowedIps"`
	TTL         int      `json:"ttl"`
}

type v2AuthRegisterFinishResponse struct {
	Registered bool               `json:"registered"`
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
	Authenticated     bool               `json:"authenticated"`
	Session           *v2AuthSessionInfo `json:"session,omitempty"`
	WrappedPrimaryKey string             `json:"wrappedPrimaryKey,omitempty"`
}

type v2AuthFinalizeSignupRequest struct {
	RequestEncEcdhPubkey  json.RawMessage `json:"requestEncEcdhPubkey"`
	RequestEncMlkemPubkey string          `json:"requestEncMlkemPubkey"`
	WrappedPrimaryKey     string          `json:"wrappedPrimaryKey,omitempty"`
}

type v2AuthAllowedIPsRequest struct {
	AllowedIPs []string `json:"allowedIps"`
}

type v2AuthSessionResponse struct {
	v2AuthSessionInfo

	Authenticated bool `json:"authenticated"`
}

type v2AuthLogoutResponse struct {
	LoggedOut bool `json:"loggedOut"`
}

type v2AuthUpdateDisplayNameRequest struct {
	DisplayName string `json:"displayName"`
}

type v2AuthUpdateWrappedKeyRequest struct {
	CredentialID      string `json:"credentialId"`
	WrappedPrimaryKey string `json:"wrappedPrimaryKey"`
}

type v2AuthCredentialItem struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	CreatedAt   int64  `json:"createdAt"`
	LastUsedAt  int64  `json:"lastUsedAt"`
}

type v2AddCredentialChallengePayload struct {
	UserID          string                   `json:"userId"`
	WebAuthnUserID  string                   `json:"webauthnUserId"`
	DisplayName     string                   `json:"displayName"`
	WebAuthnSession *webauthnlib.SessionData `json:"webauthnSession,omitempty"`
}

type v2AuthAddCredentialBeginRequest struct {
	CredentialName string `json:"credentialName"`
}

type v2AuthAddCredentialFinishRequest struct {
	ChallengeID       string          `json:"challengeId"`
	Credential        json.RawMessage `json:"credential"`
	CredentialName    string          `json:"credentialName"`
	WrappedPrimaryKey string          `json:"wrappedPrimaryKey,omitempty"`
}

type v2AuthRenameCredentialRequest struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type v2AuthDeleteCredentialRequest struct {
	ID string `json:"id"`
}

func (s *Server) RouteV2AuthRegisterBegin(c *gin.Context) {
	cfg := config.Get()
	if cfg.DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	var req v2AuthRegisterBeginRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	userID := uuid.NewString()
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	user, err := newV2WebAuthnUserForRegistration(userID, req.DisplayName)
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

	ch, err := s.authStore.BeginChallengeWithPayload(c.Request.Context(), "register", userID, session.Challenge, session.Expires, v2RegisterChallengePayload{
		UserID:          userID,
		DisplayName:     req.DisplayName,
		WebAuthnUserID:  base64.RawURLEncoding.EncodeToString(user.id),
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "challenge-delete:" + ch.ID,
		Kind:    "challenge",
		ID:      ch.ID,
		TTL:     ch.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthRegisterBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Mode:        "webauthn",
		Options:     creation,
		BasePrfSalt: cfg.GetPRFSalt(),
	})
}

func (s *Server) RouteV2AuthRegisterFinish(c *gin.Context) {
	cfg := config.Get()
	if cfg.DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	var req v2AuthRegisterFinishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required registration fields"))
		return
	}

	sess, err := s.v2RegisterFinish(c, req)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "User registration failed",
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User registered",
		slog.String("user_id", sess.UserID),
		slog.String("client_ip", c.ClientIP()),
	)

	err = s.setSessionCookie(c, sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthRegisterFinishResponse{
		Registered: true,
		Session:    sessionInfoFromSession(sess),
	})
}

func (s *Server) RouteV2AuthLoginBegin(c *gin.Context) {
	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	ch, err := s.authStore.BeginChallengeWithPayload(c.Request.Context(), "login", "", session.Challenge, session.Expires, v2LoginChallengePayload{
		Challenge:       session.Challenge,
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "challenge-delete:" + ch.ID,
		Kind:    "challenge",
		ID:      ch.ID,
		TTL:     ch.ExpiresAt.Add(10 * time.Minute),
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
	var req v2AuthLoginFinishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required login fields"))
		return
	}

	sess, credRec, err := s.v2LoginFinish(c, req)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Login failed",
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.setSessionCookie(c, sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged in",
		slog.String("user_id", sess.UserID),
		slog.String("client_ip", c.ClientIP()),
	)

	resp := v2AuthLoginFinishResponse{
		Authenticated: true,
		Session:       sessionInfoFromSession(sess),
	}

	// Throttle wrapped primary key delivery
	// The wrapped primary key is the user's encrypted root-key material; an attacker that controls a passkey
	// could otherwise call /v2/auth/login/finish in a tight loop and harvest the blob for offline password cracking
	// We refuse the login so the client cannot abuse this endpoint
	if credRec != nil && credRec.WrappedPrimaryKey != "" {
		overLimit := s.wrappedKeyLimiter.OnLimit(c.Writer, c.Request, "v2-wrapped-key:"+sess.UserID)
		if overLimit {
			// A WebAuthn-authenticated client that exceeds the budget has the new session revoked and a 429 returned
			revokeErr := s.authStore.RevokeSession(c.Request.Context(), sess.ID)
			if revokeErr != nil {
				logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
					"Failed to revoke session after wrapped-key rate-limit refusal",
					slog.String("user_id", sess.UserID),
					slog.Any("error", revokeErr),
				)
			}

			logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
				"Refused wrapped-key delivery: per-user rate limit exceeded",
				slog.String("user_id", sess.UserID),
				slog.String("client_ip", c.ClientIP()),
			)

			AbortWithErrorJSON(c, NewResponseError(http.StatusTooManyRequests, "Too many login attempts; please retry later"))
			return
		}

		resp.WrappedPrimaryKey = credRec.WrappedPrimaryKey
		logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(),
			"Delivered wrapped primary key to authenticated client",
			slog.String("user_id", sess.UserID),
			slog.String("client_ip", c.ClientIP()),
		)
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) RouteV2AuthFinalizeSignup(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthFinalizeSignupRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if len(req.RequestEncEcdhPubkey) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "requestEncEcdhPubkey is required"))
		return
	}
	if req.RequestEncMlkemPubkey == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "requestEncMlkemPubkey is required"))
		return
	}

	// Validate the ECDH public key is a valid P-256 JWK
	var ecdhPubkey protocolv2.ECP256PublicJWK
	err = json.Unmarshal(req.RequestEncEcdhPubkey, &ecdhPubkey)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid requestEncEcdhPubkey"))
		return
	}
	err = ecdhPubkey.ValidatePublic()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid requestEncEcdhPubkey: %v", err))
		return
	}

	// Validate the ML-KEM public key is valid base64
	_, err = utils.DecodeBase64String(req.RequestEncMlkemPubkey)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid requestEncMlkemPubkey format"))
		return
	}

	if req.WrappedPrimaryKey != "" && len(req.WrappedPrimaryKey) > 512 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "wrappedPrimaryKey is too large"))
		return
	}

	err = s.authStore.FinalizeSignup(c.Request.Context(), userID, req.WrappedPrimaryKey, string(req.RequestEncEcdhPubkey), req.RequestEncMlkemPubkey)
	switch {
	case errors.Is(err, db.ErrAlreadyFinalized):
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Account is already finalized"))
		return
	case errors.Is(err, db.ErrUserNotFound):
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
		return
	case err != nil:
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.deleteQueue.Dequeue("user-delete:" + userID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK,
		struct {
			OK bool `json:"ok"`
		}{
			OK: true,
		})
}

func (s *Server) RouteV2AuthAllowedIPs(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthAllowedIPsRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	allowedIPs, err := s.authStore.UpdateAllowedIPs(c.Request.Context(), userID, req.AllowedIPs)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, err.Error()))
		return
	}

	c.JSON(http.StatusOK, struct {
		OK         bool     `json:"ok"`
		AllowedIPs []string `json:"allowedIps"`
	}{
		OK:         true,
		AllowedIPs: allowedIPs,
	})
}

func (s *Server) RouteV2AuthRequestKeyRegenerate(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	requestKey, err := s.authStore.RegenerateRequestKey(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, struct {
		OK         bool   `json:"ok"`
		RequestKey string `json:"requestKey"`
	}{
		OK:         true,
		RequestKey: requestKey,
	})
}

func (s *Server) RouteV2AuthSession(c *gin.Context) {
	sessID := c.GetString(contextKeySessionID)
	if sessID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	sess, err := s.authStore.GetSession(c.Request.Context(), sessID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if sess == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	c.JSON(http.StatusOK, v2AuthSessionResponse{
		Authenticated:     true,
		v2AuthSessionInfo: *sessionInfoFromSession(sess),
	})
}

func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	id := c.GetString(contextKeySessionID)
	if id != "" {
		err := s.authStore.RevokeSession(c.Request.Context(), id)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusInternalServerError, "Failed to revoke session"))
			return
		}

		err = s.authStore.DeleteRevokedSession(c.Request.Context(), id, time.Now().UTC(), false)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		err = s.deleteQueue.Dequeue("session-delete:" + id)
		if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
			AbortWithErrorJSON(c, err)
			return
		}
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged out",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	cookieName, cookiePath := sessionCookieFor(c)
	isSecure := secureCookie(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, cookiePath, "", isSecure, true)

	c.JSON(http.StatusOK, v2AuthLogoutResponse{
		LoggedOut: true,
	})
}

func (s *Server) RouteV2AuthUpdateDisplayName(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthUpdateDisplayNameRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	err = s.authStore.UpdateDisplayName(c.Request.Context(), userID, req.DisplayName)
	switch {
	case errors.Is(err, db.ErrDisplayNameTooLong):
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Display name is too long"))
		return
	case errors.Is(err, db.ErrUserNotFound):
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
		return
	case err != nil:
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, struct {
		OK          bool   `json:"ok"`
		DisplayName string `json:"displayName"`
	}{
		OK:          true,
		DisplayName: strings.TrimSpace(req.DisplayName),
	})
}

func (s *Server) RouteV2AuthUpdateWrappedKey(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthUpdateWrappedKeyRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.CredentialID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "credentialId is required"))
		return
	}

	// Refuse the update while an add-credential WebAuthn ceremony is in flight for this user
	// The in-flight ceremony will wrap the new credential's primary key with the current password, and letting the password change land in between would leave that new credential wrapped with the old password while the signed-in credential picks up the new one
	pending, err := s.authStore.HasPendingChallenge(c.Request.Context(), userID, "add-credential")
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusInternalServerError, "Failed to check pending challenges"))
		return
	}
	if pending {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Cannot change password while a passkey registration is in progress"))
		return
	}

	err = s.authStore.UpdateCredentialWrappedKey(c.Request.Context(), req.CredentialID, userID, req.WrappedPrimaryKey)
	if errors.Is(err, db.ErrCredentialNotFound) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Credential not found"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, err.Error()))
		return
	}

	c.JSON(http.StatusOK, struct {
		OK bool `json:"ok"`
	}{
		OK: true,
	})
}

func (s *Server) RouteV2AuthListCredentials(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	records, err := s.authStore.ListCredentials(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	items := make([]v2AuthCredentialItem, len(records))
	for i, rec := range records {
		items[i] = v2AuthCredentialItem{
			ID:          rec.ID,
			DisplayName: rec.DisplayName,
			CreatedAt:   rec.CreatedAt,
			LastUsedAt:  rec.LastUsedAt,
		}
	}

	c.JSON(http.StatusOK, items)
}

func (s *Server) RouteV2AuthAddCredentialBegin(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthAddCredentialBeginRequest
	_ = c.ShouldBindJSON(&req)

	// Load the existing user with their current credentials to populate excludeCredentials
	userRecord, err := s.v2LoadWebAuthnUser(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if userRecord == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
		return
	}

	creation, session, err := s.webAuthn.BeginRegistration(userRecord,
		webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthnlib.WithExtensions(protocol.AuthenticationExtensions{
			"prf": map[string]any{},
		}),
	)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	ch, err := s.authStore.BeginChallengeWithPayload(c.Request.Context(), "add-credential", userID, session.Challenge, session.Expires, v2AddCredentialChallengePayload{
		UserID:          userID,
		WebAuthnUserID:  base64.RawURLEncoding.EncodeToString(userRecord.id),
		DisplayName:     strings.TrimSpace(req.CredentialName),
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "challenge-delete:" + ch.ID,
		Kind:    "challenge",
		ID:      ch.ID,
		TTL:     ch.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, struct {
		ChallengeID string `json:"challengeId"`
		Challenge   string `json:"challenge"`
		ExpiresAt   int64  `json:"expiresAt"`
		Options     any    `json:"options,omitempty"`
		BasePrfSalt string `json:"basePrfSalt"`
	}{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Options:     creation,
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

func (s *Server) RouteV2AuthAddCredentialFinish(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthAddCredentialFinishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required fields"))
		return
	}

	var payload v2AddCredentialChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "add-credential", &payload)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if !ok {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Challenge is invalid or expired"))
		return
	}

	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	// Verify the challenge belongs to the authenticated user
	if payload.UserID != userID {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Challenge does not belong to this user"))
		return
	}

	if payload.WebAuthnSession == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Challenge is missing WebAuthn session data"))
		return
	}

	// Load the user record with existing credentials for the verification
	userRecord, err := s.v2LoadWebAuthnUser(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if userRecord == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "User not found"))
		return
	}

	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	cred, err := s.webAuthn.FinishRegistration(userRecord, *payload.WebAuthnSession, waReq)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err))
		return
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Use the credential name from the finish request, falling back to the begin request
	credName := strings.TrimSpace(req.CredentialName)
	if credName == "" {
		credName = payload.DisplayName
	}

	if req.WrappedPrimaryKey != "" && len(req.WrappedPrimaryKey) > 512 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "wrappedPrimaryKey is too large"))
		return
	}

	err = s.authStore.AddCredential(c.Request.Context(), db.AddCredentialInput{
		UserID:            userID,
		CredentialID:      base64.RawURLEncoding.EncodeToString(cred.ID),
		DisplayName:       credName,
		PublicKey:         string(credJSON),
		SignCount:         int64(cred.Authenticator.SignCount),
		WrappedPrimaryKey: req.WrappedPrimaryKey,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Credential added to user",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, struct {
		OK bool `json:"ok"`
	}{
		OK: true,
	})
}

func (s *Server) RouteV2AuthRenameCredential(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthRenameCredentialRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "id is required"))
		return
	}

	err = s.authStore.RenameCredential(c.Request.Context(), req.ID, userID, req.DisplayName)
	switch {
	case errors.Is(err, db.ErrDisplayNameTooLong):
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Display name is too long"))
		return
	case errors.Is(err, db.ErrCredentialNotFound):
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Credential not found"))
		return
	case err != nil:
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, struct {
		OK bool `json:"ok"`
	}{
		OK: true,
	})
}

func (s *Server) RouteV2AuthDeleteCredential(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req v2AuthDeleteCredentialRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "id is required"))
		return
	}

	err = s.authStore.DeleteCredential(c.Request.Context(), req.ID, userID)
	switch {
	case errors.Is(err, db.ErrLastCredential):
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Cannot delete the last credential"))
		return
	case errors.Is(err, db.ErrCredentialNotFound):
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Credential not found"))
		return
	case err != nil:
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Credential deleted",
		slog.String("user_id", userID),
		slog.String("credential_id", req.ID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, struct {
		OK bool `json:"ok"`
	}{
		OK: true,
	})
}

func (s *Server) setSessionCookie(c *gin.Context, sess *db.AuthSession) error {
	if sess == nil {
		return NewResponseError(http.StatusInternalServerError, "session is nil")
	}

	ttl := max(time.Until(sess.ExpiresAt), time.Second)

	cookieName, cookiePath := sessionCookieFor(c)
	c.SetSameSite(http.SameSiteLaxMode)
	return setSecureCookie(c, cookieName, sess.ID, ttl, cookiePath, secureCookie(c), true, serializeSecureCookieEncryptedJWT)
}

func secureCookie(c *gin.Context) bool {
	url := location.Get(c)
	return url.Scheme == "https" || config.Get().ForceSecureCookies
}

func (s *Server) v2RegisterFinish(c *gin.Context, req v2AuthRegisterFinishRequest) (*db.AuthSession, error) {
	var payload v2RegisterChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "register", &payload)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	}

	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		return nil, err
	}

	if payload.WebAuthnSession == nil {
		return nil, NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}

	displayName := payload.DisplayName
	if displayName == "" {
		displayName = payload.UserID
	}
	user := &v2WebAuthnUser{
		id:          payload.WebAuthnSession.UserID,
		userID:      payload.UserID,
		displayName: displayName,
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

	sess, err := s.authStore.RegisterUser(c.Request.Context(), db.RegisterUserInput{
		UserID:         payload.UserID,
		DisplayName:    payload.DisplayName,
		WebAuthnUserID: payload.WebAuthnUserID,
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      string(credJSON),
		SignCount:      int64(cred.Authenticator.SignCount),
		SessionTTL:     config.Get().SessionTimeout,
	})
	if errors.Is(err, db.ErrUserAlreadyExists) {
		return nil, NewResponseError(http.StatusConflict, "User already exists")
	} else if err != nil {
		return nil, err
	}

	// Register the non-ready user for cleanup if it's not completed in 24 hours
	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "user-delete:" + sess.UserID,
		Kind:    "nonready-user",
		ID:      sess.UserID,
		TTL:     sess.CreatedAt.Add(24*time.Hour + time.Minute),
	})
	if err != nil {
		return nil, err
	}

	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "session-delete:" + sess.ID,
		Kind:    "session",
		ID:      sess.ID,
		TTL:     sess.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func (s *Server) v2LoginFinish(c *gin.Context, req v2AuthLoginFinishRequest) (*db.AuthSession, *db.AuthCredentialRecord, error) {
	var payload v2LoginChallengePayload
	ok, err := s.authStore.ConsumeChallengePayload(c.Request.Context(), req.ChallengeID, "login", &payload)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	}

	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		return nil, nil, err
	}

	if payload.WebAuthnSession == nil {
		return nil, nil, NewResponseError(http.StatusConflict, "Login challenge is missing WebAuthn session data")
	}

	var (
		discoveredUser   *v2WebAuthnUser
		discoveredDBUser *db.User
	)
	handler := func(rawID, userHandle []byte) (webauthnlib.User, error) {
		webAuthnUserID := base64.RawURLEncoding.EncodeToString(userHandle)
		user, hErr := s.authStore.GetUserByWebAuthnUserID(c.Request.Context(), webAuthnUserID)
		if hErr != nil {
			return nil, hErr
		}
		if user == nil || user.Status != "active" {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}

		userRecord, hErr := s.v2LoadWebAuthnUser(c.Request.Context(), user.ID)
		if hErr != nil {
			return nil, hErr
		}
		if userRecord == nil {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}

		discoveredDBUser = user
		discoveredUser = userRecord
		return userRecord, nil
	}

	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return nil, nil, err
	}

	cred, err := s.webAuthn.FinishDiscoverableLogin(handler, *payload.WebAuthnSession, waReq)
	if err != nil {
		return nil, nil, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn login verification failed: %v", err)
	}
	if discoveredUser == nil || discoveredDBUser == nil {
		return nil, nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	err = s.validateAuthenticatorSignCount(c, discoveredUser, cred)
	if err != nil {
		return nil, nil, err
	}

	sess, err := s.createLoginSession(c.Request.Context(), discoveredUser.userID, cred)
	if err != nil {
		if errors.Is(err, db.ErrInvalidLogin) {
			return nil, nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}
		return nil, nil, err
	}

	// Look up the credential record so the caller can access the per-credential wrapped primary key
	credRec, err := s.authStore.GetCredentialByCredentialID(c.Request.Context(), base64.RawURLEncoding.EncodeToString(cred.ID), discoveredUser.userID)
	if err != nil {
		return nil, nil, err
	}

	return sess, credRec, nil
}

func (s *Server) validateAuthenticatorSignCount(c *gin.Context, userRecord *v2WebAuthnUser, cred *webauthnlib.Credential) error {
	// Detect possible cloned authenticator by comparing the returned sign count with the stored value.
	// If the stored count was non-zero but the new count is not strictly greater, the credential may have been cloned.
	// Note: Some authenticators do not report a counter, which is always 0.
	newCount := cred.Authenticator.SignCount

	credIDEncoded := base64.RawURLEncoding.EncodeToString(cred.ID)
	for _, stored := range userRecord.credentials {
		if base64.RawURLEncoding.EncodeToString(stored.ID) != credIDEncoded {
			continue
		}

		// Authenticators that don't implement a sign counter always report 0
		// In that case we cannot detect cloning, but we still need to match the credential in the user's stored list.
		if newCount == 0 {
			return nil
		}

		storedCount := stored.Authenticator.SignCount
		if storedCount > 0 && newCount <= storedCount {
			logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
				"Possible cloned authenticator: sign count did not increase",
				slog.String("user_id", userRecord.userID),
				slog.String("credential_id", credIDEncoded),
				slog.Uint64("stored_sign_count", uint64(storedCount)),
				slog.Uint64("new_sign_count", uint64(newCount)),
				slog.String("client_ip", c.ClientIP()),
			)
			return NewResponseError(http.StatusForbidden, "Authenticator sign count anomaly detected — possible credential cloning")
		}
		return nil
	}

	// Fail-closed: if the credential that signed the assertion isn't in the
	// user's stored credential list, refuse the login. This should be
	// unreachable because FinishDiscoverableLogin already matched a stored
	// credential, but we want a defense-in-depth guarantee against a future
	// refactor that reorders the lookups.
	logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
		"Authenticator credential not found in user's stored credentials",
		slog.String("user_id", userRecord.userID),
		slog.String("credential_id", credIDEncoded),
		slog.String("client_ip", c.ClientIP()),
	)
	return NewResponseError(http.StatusForbidden, "Authenticator credential not recognized")
}

func (s *Server) createLoginSession(ctx context.Context, userID string, cred *webauthnlib.Credential) (*db.AuthSession, error) {
	sess, err := s.authStore.Login(ctx, db.LoginInput{
		UserID:       userID,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID),
		SignCount:    int64(cred.Authenticator.SignCount),
		SessionTTL:   config.Get().SessionTimeout,
	})
	if err != nil {
		return nil, err
	}

	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "session-delete:" + sess.ID,
		Kind:    "session",
		ID:      sess.ID,
		TTL:     sess.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		return nil, err
	}

	return sess, nil
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
	userID      string
	displayName string
	credentials []webauthnlib.Credential
}

func newV2WebAuthnUserForRegistration(userID string, displayName string) (*v2WebAuthnUser, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	if displayName == "" {
		displayName = userID
	}
	return &v2WebAuthnUser{
		id:          id,
		userID:      userID,
		displayName: displayName,
	}, nil
}

func (u *v2WebAuthnUser) WebAuthnID() []byte                            { return u.id }
func (u *v2WebAuthnUser) WebAuthnName() string                          { return u.userID }
func (u *v2WebAuthnUser) WebAuthnDisplayName() string                   { return u.displayName }
func (u *v2WebAuthnUser) WebAuthnCredentials() []webauthnlib.Credential { return u.credentials }

func (s *Server) v2LoadWebAuthnUser(ctx context.Context, userID string) (*v2WebAuthnUser, error) {
	user, err := s.authStore.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, nil
	}

	records, err := s.authStore.ListCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}

	creds := make([]webauthnlib.Credential, 0, len(records))
	for _, rec := range records {
		var cred webauthnlib.Credential
		err = json.Unmarshal([]byte(rec.PublicKey), &cred)
		if err != nil {
			continue
		}

		// The DB stores sign_count as int64 to accommodate any authenticator, but the webauthn library exposes it as uint32
		// Guard against silent wrap-around: a wrap to 0 (or any smaller value) would look like a replay and either lock out the user or conceal a real clone
		// Reject the credential and log it instead of narrowing
		if rec.SignCount < 0 || rec.SignCount > math.MaxUint32 {
			logging.LogFromContext(ctx).WarnContext(ctx,
				"Credential sign count out of uint32 range; skipping credential",
				slog.String("user_id", userID),
				slog.String("credential_id", rec.CredentialID),
				slog.Int64("sign_count", rec.SignCount),
			)
			continue
		}

		cred.Authenticator.SignCount = uint32(rec.SignCount)
		creds = append(creds, cred)
	}
	if len(creds) == 0 {
		return nil, nil
	}

	decodedUserID := []byte(user.ID)
	if user.WebAuthnUserID != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(user.WebAuthnUserID)
		if err == nil {
			decodedUserID = decoded
		}
	}

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.ID
	}

	return &v2WebAuthnUser{
		id:          decodedUserID,
		userID:      user.ID,
		displayName: displayName,
		credentials: creds,
	}, nil
}

func sessionInfoFromSession(sess *db.AuthSession) *v2AuthSessionInfo {
	if sess == nil {
		return nil
	}
	allowedIPs := sess.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}
	return &v2AuthSessionInfo{
		UserID:      sess.UserID,
		DisplayName: sess.DisplayName,
		RequestKey:  sess.RequestKey,
		AllowedIPs:  allowedIPs,
		TTL:         int(time.Until(sess.ExpiresAt).Seconds()),
	}
}
