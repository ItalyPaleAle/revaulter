package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	UserID          string   `json:"userId"`
	DisplayName     string   `json:"displayName"`
	RequestKey      string   `json:"requestKey"`
	WrappedKeyEpoch int64    `json:"wrappedKeyEpoch"`
	AllowedIPs      []string `json:"allowedIps"`
	TTL             int      `json:"ttl"`
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
	Authenticated             bool               `json:"authenticated"`
	Session                   *v2AuthSessionInfo `json:"session,omitempty"`
	WrappedPrimaryKey         string             `json:"wrappedPrimaryKey,omitempty"`
	WrappedAnchorKey          string             `json:"wrappedAnchorKey,omitempty"`
	CredentialWrappedKeyEpoch int64              `json:"credentialWrappedKeyEpoch,omitempty"`
	WrappedKeyStale           bool               `json:"wrappedKeyStale"`
}

type v2AuthFinalizeSignupRequest struct {
	RequestEncEcdhPubkey  json.RawMessage `json:"requestEncEcdhPubkey"`
	RequestEncMlkemPubkey string          `json:"requestEncMlkemPubkey"`
	WrappedPrimaryKey     string          `json:"wrappedPrimaryKey,omitempty"`

	// Hybrid anchor (long-lived identity root)
	AnchorEs384PublicKey   string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string `json:"anchorMldsa87PublicKey"`

	// Self-signatures by the anchor over the canonical pubkey bundle
	PubkeyBundleSignatureEs384   string `json:"pubkeyBundleSignatureEs384"`
	PubkeyBundleSignatureMldsa87 string `json:"pubkeyBundleSignatureMldsa87"`

	// First-credential attestation signed by the anchor
	WrappedAnchorKey            string `json:"wrappedAnchorKey"`
	AttestationPayload          string `json:"attestationPayload"`
	AttestationSignatureEs384   string `json:"attestationSignatureEs384"`
	AttestationSignatureMldsa87 string `json:"attestationSignatureMldsa87"`
}

type v2AuthFinalizeSignupResponse struct {
	OK      bool               `json:"ok"`
	Session *v2AuthSessionInfo `json:"session,omitempty"`
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

type v2AuthOKResponse struct {
	OK bool `json:"ok"`
}

type v2AuthAllowedIPsResponse struct {
	OK         bool     `json:"ok"`
	AllowedIPs []string `json:"allowedIps"`
}

type v2AuthRequestKeyResponse struct {
	OK         bool   `json:"ok"`
	RequestKey string `json:"requestKey"`
}

type v2AuthDisplayNameResponse struct {
	OK          bool   `json:"ok"`
	DisplayName string `json:"displayName"`
}

type v2AuthAddCredentialBeginResponse struct {
	ChallengeID string `json:"challengeId"`
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expiresAt"`
	Options     any    `json:"options,omitempty"`
	BasePrfSalt string `json:"basePrfSalt"`
}

type v2AuthUpdateDisplayNameRequest struct {
	DisplayName string `json:"displayName"`
}

type v2AuthUpdateWrappedKeyRequest struct {
	CredentialID      string `json:"credentialId"`
	WrappedPrimaryKey string `json:"wrappedPrimaryKey"`
	WrappedAnchorKey  string `json:"wrappedAnchorKey"`
	AdvanceEpoch      bool   `json:"advanceEpoch"`
}

type v2AuthCredentialItem struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	WrappedKeyEpoch int64  `json:"wrappedKeyEpoch"`
	WrappedKeyStale bool   `json:"wrappedKeyStale"`
	CreatedAt       int64  `json:"createdAt"`
	LastUsedAt      int64  `json:"lastUsedAt"`
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

	// New credentials must carry a hybrid attestation signed by the user's anchor
	WrappedAnchorKey            string `json:"wrappedAnchorKey"`
	AttestationPayload          string `json:"attestationPayload"`
	AttestationSignatureEs384   string `json:"attestationSignatureEs384"`
	AttestationSignatureMldsa87 string `json:"attestationSignatureMldsa87"`
}

type v2AuthRenameCredentialRequest struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type v2AuthDeleteCredentialRequest struct {
	ID string `json:"id"`
}

//nolint:errname
var noSessionResponseError = NewResponseError(http.StatusUnauthorized, "No session")

// RouteV2AuthRegisterBegin is the handler for POST /v2/auth/register/begin
func (s *Server) RouteV2AuthRegisterBegin(c *gin.Context) {
	cfg := config.Get()

	// Stop if account creation is disabled
	if cfg.DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	// Parse the request body
	var req v2AuthRegisterBeginRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	// Create the user object for registration
	userID := uuid.NewString()
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	user, err := newV2WebAuthnUserForRegistration(userID, req.DisplayName)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Begin the WebAuthn registration session
	creation, session, err := s.beginWebAuthnSession(user)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Store the challenge in the database
	// BeginChallenge must be executed in a transaction
	ch, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		return tx.AuthStore().BeginChallenge(ctx, "register", userID, session.Challenge, session.Expires, v2RegisterChallengePayload{
			UserID:          userID,
			DisplayName:     req.DisplayName,
			WebAuthnUserID:  base64.RawURLEncoding.EncodeToString(user.id),
			WebAuthnSession: session,
		})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Add the challenge to the cleanup queue
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

	// Send response
	c.JSON(http.StatusOK, v2AuthRegisterBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Mode:        "webauthn",
		Options:     creation,
		BasePrfSalt: cfg.GetPRFSalt(),
	})
}

func (s *Server) beginWebAuthnSession(user *v2WebAuthnUser) (creation *protocol.CredentialCreation, session *webauthnlib.SessionData, err error) {
	// Begin the WebAuthn registration session
	return s.webAuthn.BeginRegistration(user,
		// We require discoverable credentials aka Passkeys
		webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		// Add PRF extension
		webauthnlib.WithExtensions(protocol.AuthenticationExtensions{
			"prf": map[string]any{},
		}),
	)
}

// RouteV2AuthRegisterFinish is the handler for POST /v2/auth/register/finish
func (s *Server) RouteV2AuthRegisterFinish(c *gin.Context) {
	cfg := config.Get()

	// Stop if account creation is disabled
	if cfg.DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	// Parse and validate the request body
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

	// Complete the registration
	// This must be executed in a transaction
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (registerFinishRes, error) {
		return s.registerFinish(c, tx, req)
	})
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "User registration failed",
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	// Register the non-ready user for cleanup if it's not completed in 24 hours
	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "user-delete:" + res.user.ID,
		Kind:    "nonready-user",
		ID:      res.user.ID,
		TTL:     time.Now().UTC().Add(24*time.Hour + time.Minute),
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Set the session cookie
	err = setSessionCookie(c, res.sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User registered",
		slog.String("user_id", res.user.ID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Respond
	c.JSON(http.StatusOK, v2AuthRegisterFinishResponse{
		Registered: true,
		Session:    sessionInfoFromUser(res.user, int(max(time.Until(res.sess.ExpiresAt), 0).Seconds())),
	})
}

// RouteV2AuthLoginBegin is the handler for POST /v2/auth/login/begin
func (s *Server) RouteV2AuthLoginBegin(c *gin.Context) {
	// Get an assertion and store it in the database
	assertion, session, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// BeginChallenge must be executed in a transaction
	ch, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		return tx.AuthStore().BeginChallenge(ctx, "login", "", session.Challenge, session.Expires, v2LoginChallengePayload{
			Challenge:       session.Challenge,
			WebAuthnSession: session,
		})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Enqueue the challenge for cleanup when it expires
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

	// Respond
	c.JSON(http.StatusOK, v2AuthLoginBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   session.Challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
		Mode:        "webauthn",
		Options:     assertion,
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

// RouteV2AuthLoginFinish is the handler for POST /v2/auth/login/finish
func (s *Server) RouteV2AuthLoginFinish(c *gin.Context) {
	// Parse the request body
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

	// Finish the login
	// This must be executed in a transaction
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (loginFinishRes, error) {
		return s.loginFinish(c, tx, req)
	})
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Login failed",
			slog.String("client_ip", c.ClientIP()),
		)
		AbortWithErrorJSON(c, err)
		return
	}

	// Remove the challenge from the cleanup queue
	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	// Create the response object
	resp := v2AuthLoginFinishResponse{
		Authenticated: true,
		Session:       sessionInfoFromUser(res.user, int(max(time.Until(res.sess.ExpiresAt), 0).Seconds())),
	}

	// Throttle wrapped primary key delivery
	// The wrapped primary key is the user's encrypted root-key material:
	// an attacker that controls a passkey could otherwise call /v2/auth/login/finish in a tight loop and harvest the blob for offline password cracking
	// We refuse the login so the client cannot abuse this endpoint
	logMsg := "User logged in"
	if res.cred != nil && res.cred.WrappedPrimaryKey != "" {
		resp.CredentialWrappedKeyEpoch = res.cred.WrappedKeyEpoch
		resp.WrappedKeyStale = res.cred.WrappedKeyEpoch > 0 && res.cred.WrappedKeyEpoch < res.user.WrappedKeyEpoch
		overLimit := s.wrappedKeyLimiter.OnLimit(c.Writer, c.Request, "v2-wrapped-key:"+res.user.ID)
		if overLimit {
			// A WebAuthn-authenticated client that exceeds the budget has a 429 returned
			logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
				"Refused wrapped-key delivery: per-user rate limit exceeded",
				slog.String("user_id", res.user.ID),
				slog.String("client_ip", c.ClientIP()),
			)

			AbortWithErrorJSON(c, NewResponseError(http.StatusTooManyRequests, "Too many login attempts; please retry later"))
			return
		}

		resp.WrappedPrimaryKey = res.cred.WrappedPrimaryKey
		resp.WrappedAnchorKey = res.cred.WrappedAnchorKey
		logMsg = "User logged in and delivered wrapped primary key"
	}

	// Set the session cookie only after the rate-limit gate has passed
	err = setSessionCookie(c, res.sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), logMsg,
		slog.String("user_id", res.user.ID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Send the response
	c.JSON(http.StatusOK, resp)
}

// RouteV2AuthFinalizeSignup is the handler for POST /v2/auth/finalize-signup
func (s *Server) RouteV2AuthFinalizeSignup(c *gin.Context) {
	cfg := config.Get()

	// Stop if account creation is disabled
	if cfg.DisableSignup {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Account creation is disabled"))
		return
	}

	// Get the user from the context
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse and validate the request body
	var req v2AuthFinalizeSignupRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	err = validateV2AuthFinalizeSignupRequest(&req)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Validate and verify the anchor material
	// We require both halves of the hybrid (ES384 + ML-DSA-87) to verify over both the pubkey bundle (so the CLI can pin the anchor at first contact) and the first credential's attestation (so the credential is provably bound to the user's identity root, not just to the server's DB)

	// To start, parse the ECDSA and ML-DSA anchor public keys
	anchorEs384Pub, mldsa87PubBytes, err := parseAnchorPubkeys(req.AnchorEs384PublicKey, req.AnchorMldsa87PublicKey)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid anchor public key: %v", err))
		return
	}

	// Parse the bundle signature
	bundleSigEs, bundleSigMl, err := parseHybridSignatures(req.PubkeyBundleSignatureEs384, req.PubkeyBundleSignatureMldsa87)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid pubkeyBundleSignature: %v", err))
		return
	}

	// Parse the attestation signature
	attestSigEs, attestSigMl, err := parseHybridSignatures(req.AttestationSignatureEs384, req.AttestationSignatureMldsa87)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid attestationSignature: %v", err))
		return
	}

	// Extract the attestation payload
	attestPayload, err := protocolv2.ParseAttestationPayload(req.AttestationPayload)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid attestationPayload: %v", err))
		return
	}

	// Rest of the method requires a transaction
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (finalizeSetupRes, error) {
		return s.finalizeSetup(c, tx, finalizeSetupVals{
			userID:          userID,
			req:             &req,
			anchorEs384Pub:  anchorEs384Pub,
			mldsa87PubBytes: mldsa87PubBytes,
			bundleSigEs:     bundleSigEs,
			bundleSigMl:     bundleSigMl,
			attestSigEs:     attestSigEs,
			attestSigMl:     attestSigMl,
			attestPayload:   &attestPayload,
		})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Remove the now-ready user from the cleanup queue
	err = s.deleteQueue.Dequeue("user-delete:" + userID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	// Create the new session token, where the user is ready
	sess, err := newAuthSessionToken(res.user, config.Get().SessionTimeout)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Set the updated session cookie
	err = setSessionCookie(c, sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send the response
	c.JSON(http.StatusOK, v2AuthFinalizeSignupResponse{
		OK:      true,
		Session: sessionInfoFromUser(res.user, int(max(time.Until(sess.ExpiresAt), 0).Seconds())),
	})
}

func validateV2AuthFinalizeSignupRequest(req *v2AuthFinalizeSignupRequest) error {
	if len(req.RequestEncEcdhPubkey) == 0 {
		return NewResponseError(http.StatusBadRequest, "requestEncEcdhPubkey is required")
	}
	if req.RequestEncMlkemPubkey == "" {
		return NewResponseError(http.StatusBadRequest, "requestEncMlkemPubkey is required")
	}

	// Validate the ECDH public key is a valid P-256 JWK
	var ecdhPubkey protocolv2.ECP256PublicJWK
	err := json.Unmarshal(req.RequestEncEcdhPubkey, &ecdhPubkey)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid requestEncEcdhPubkey")
	}
	err = ecdhPubkey.ValidatePublic()
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "invalid requestEncEcdhPubkey: %v", err)
	}

	// Validate the ML-KEM public key is valid base64
	mlkemKey, err := utils.DecodeBase64String(req.RequestEncMlkemPubkey)
	if err != nil || len(mlkemKey) != mlkem.EncapsulationKeySize768 {
		return NewResponseError(http.StatusBadRequest, "invalid requestEncMlkemPubkey")
	}

	// Enforce max length on the wrapped primary key
	if req.WrappedPrimaryKey == "" || len(req.WrappedPrimaryKey) > 512 {
		return NewResponseError(http.StatusBadRequest, "invalid wrappedPrimaryKey")
	}

	err = validateWrappedAnchorEnvelope(req.WrappedAnchorKey)
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "invalid wrappedAnchorKey: %v", err)
	}

	return nil
}

// RouteV2AuthAllowedIPs is the handler for POST /v2/auth/allowed-ips
func (s *Server) RouteV2AuthAllowedIPs(c *gin.Context) {
	// Get the user ID
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
	var req v2AuthAllowedIPsRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	// Update in the database
	allowedIPs, err := s.db.AuthStore().UpdateAllowedIPs(c.Request.Context(), userID, req.AllowedIPs)
	if errors.Is(err, db.ErrInvalidIP) || errors.Is(err, db.ErrInvalidCIDR) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, err.Error()))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthAllowedIPsResponse{
		OK:         true,
		AllowedIPs: allowedIPs,
	})
}

// RouteV2AuthRequestKeyRegenerate is the handler for POST /v2/auth/regenerate-request-key
func (s *Server) RouteV2AuthRequestKeyRegenerate(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Rotate the request key
	requestKey, err := s.db.AuthStore().RegenerateRequestKey(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthRequestKeyResponse{
		OK:         true,
		RequestKey: requestKey,
	})
}

// RouteV2AuthSession is the handler for /v2/auth/session
func (s *Server) RouteV2AuthSession(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Load the user, making sure it's in active status
	user, err := s.db.AuthStore().GetUserByID(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil || user.Status != "active" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Get the TTL
	var ttl int
	ttlVal, ok := c.Get(contextKeySessionTTL)
	if ok {
		ttlInt, ok := ttlVal.(int)
		if ok && ttlInt > 0 {
			ttl = ttlInt
		}
	}

	// Send response
	info := sessionInfoFromUser(user, ttl)
	c.JSON(http.StatusOK, v2AuthSessionResponse{
		Authenticated:     true,
		v2AuthSessionInfo: *info,
	})
}

// RouteV2AuthLogout is the handler for POST /v2/auth/logout
// Note that the logout sends cookies to clear existing sessions, but doesn't invalidate issued session tokens
func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged out",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Clear both possible cookie names so a scheme change between login and logout (e.g. a proxy switching https→http) cannot leave a stray session cookie behind
	// __Host- is only legal on Secure cookies, so we must emit each with the secure flag that matches its prefix
	isSecure := secureCookie(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieNameSecure, "", -1, "/", "", true, true)
	c.SetCookie(sessionCookieNameInsecure, "", -1, "/v2", "", isSecure, true)

	// Send response
	c.JSON(http.StatusOK, v2AuthLogoutResponse{
		LoggedOut: true,
	})
}

// RouteV2AuthUpdateDisplayName is the handler for /v2/auth/update-display-name
func (s *Server) RouteV2AuthUpdateDisplayName(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
	var req v2AuthUpdateDisplayNameRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	// Update the name in the database
	err = s.db.AuthStore().UpdateDisplayName(c.Request.Context(), userID, req.DisplayName)
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

	// Send response
	c.JSON(http.StatusOK, v2AuthDisplayNameResponse{
		OK:          true,
		DisplayName: req.DisplayName,
	})
}

// RouteV2AuthUpdateWrappedKey is the handler for POST /v2/auth/update-wrapped-key
func (s *Server) RouteV2AuthUpdateWrappedKey(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
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

	// Structurally validate the wrapped-anchor envelope before persistence
	// An empty value means the caller is not updating the anchor for this credential, so only validate when non-empty
	if req.WrappedAnchorKey != "" {
		err = validateWrappedAnchorEnvelope(req.WrappedAnchorKey)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid wrappedAnchorKey: %v", err))
			return
		}
	}

	// Rest of the method must run in a transaction
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		return struct{}{}, s.updateWrappedKey(ctx, tx, userID, &req)
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

func (s *Server) updateWrappedKey(ctx context.Context, tx *db.DbTx, userID string, req *v2AuthUpdateWrappedKeyRequest) error {
	as := tx.AuthStore()

	// Refuse the update while an add-credential WebAuthn ceremony is in flight for this user
	// The in-flight ceremony will wrap the new credential's primary key with the current password, and letting the password change land in between would leave that new credential wrapped with the old password while the signed-in credential picks up the new one
	pending, err := as.HasPendingChallenge(ctx, userID, "add-credential")
	if err != nil {
		return NewResponseError(http.StatusInternalServerError, "Failed to check pending challenges")
	}
	if pending {
		return NewResponseError(http.StatusConflict, "Cannot change password while a passkey registration is in progress")
	}

	if req.AdvanceEpoch {
		_, err = as.AdvanceWrappedKeyEpoch(ctx, userID)
		if errors.Is(err, db.ErrUserNotFound) {
			return NewResponseError(http.StatusNotFound, "User not found")
		} else if err != nil {
			return NewResponseError(http.StatusInternalServerError, "Failed to update password state")
		}
	}

	err = as.UpdateCredentialWrappedKey(ctx, req.CredentialID, userID, req.WrappedPrimaryKey, req.WrappedAnchorKey)
	if errors.Is(err, db.ErrCredentialNotFound) {
		return NewResponseError(http.StatusNotFound, "Credential not found")
	} else if err != nil {
		return NewResponseError(http.StatusBadRequest, err.Error())
	}

	return nil
}

// RouteV2AuthListCredentials is the handler for GET /v2/auth/credentials
func (s *Server) RouteV2AuthListCredentials(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	as := s.db.AuthStore()

	// Get the user and ensure it's active
	// We don't need a transaction here as we're just reading data
	user, err := as.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil || user.Status != "active" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// List all credentials
	records, err := as.ListCredentials(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	items := make([]v2AuthCredentialItem, len(records))
	for i, rec := range records {
		items[i] = v2AuthCredentialItem{
			ID:              rec.ID,
			DisplayName:     rec.DisplayName,
			WrappedKeyEpoch: rec.WrappedKeyEpoch,
			WrappedKeyStale: rec.WrappedKeyEpoch > 0 && rec.WrappedKeyEpoch < user.WrappedKeyEpoch,
			CreatedAt:       rec.CreatedAt,
			LastUsedAt:      rec.LastUsedAt,
		}
	}

	c.JSON(http.StatusOK, items)
}

// RouteV2AuthAddCredentialBegin is the handler for POST /v2/auth/credentials/add/begin
func (s *Server) RouteV2AuthAddCredentialBegin(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse request body
	var req v2AuthAddCredentialBeginRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	// Rest of the method must run in a transaction
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (addCredentialBeginRes, error) {
		return s.addCredentialBegin(c.Request.Context(), tx, userID, &req)
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Enqueue the challenge to be cleaned up
	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "challenge-delete:" + res.challenge.ID,
		Kind:    "challenge",
		ID:      res.challenge.ID,
		TTL:     res.challenge.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthAddCredentialBeginResponse{
		ChallengeID: res.challenge.ID,
		Challenge:   res.session.Challenge,
		ExpiresAt:   res.challenge.ExpiresAt.Unix(),
		Options:     res.creation,
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

type addCredentialBeginRes struct {
	creation  *protocol.CredentialCreation
	session   *webauthnlib.SessionData
	challenge *db.AuthChallenge
}

func (s *Server) addCredentialBegin(ctx context.Context, tx *db.DbTx, userID string, req *v2AuthAddCredentialBeginRequest) (addCredentialBeginRes, error) {
	as := tx.AuthStore()

	// The session JWT's Ready claim is a snapshot from token mint time
	// Re-check the stored user to reject accounts disabled or un-readied after the session was issued
	// ...besides, we need to user object
	storedUser, err := as.GetUserByID(ctx, userID)
	if err != nil {
		return addCredentialBeginRes{}, err
	}
	if storedUser == nil || storedUser.Status != "active" || !storedUser.Ready {
		return addCredentialBeginRes{}, NewResponseError(http.StatusForbidden, "User account is not active")
	}

	// Load the existing user with their current credentials to populate excludeCredentials
	userRecord, err := loadWebAuthnUser(ctx, as, storedUser)
	if err != nil {
		return addCredentialBeginRes{}, err
	}
	if userRecord == nil {
		return addCredentialBeginRes{}, NewResponseError(http.StatusNotFound, "User not found")
	}

	// Begin the WebAuthn registration
	// Begin the WebAuthn registration session
	creation, session, err := s.beginWebAuthnSession(userRecord)
	if err != nil {
		return addCredentialBeginRes{}, err
	}

	ch, err := as.BeginChallenge(ctx, "add-credential", userID, session.Challenge, session.Expires, v2AddCredentialChallengePayload{
		UserID:          userID,
		WebAuthnUserID:  base64.RawURLEncoding.EncodeToString(userRecord.id),
		DisplayName:     strings.TrimSpace(req.CredentialName),
		WebAuthnSession: session,
	})
	if err != nil {
		return addCredentialBeginRes{}, err
	}

	return addCredentialBeginRes{
		creation:  creation,
		session:   session,
		challenge: ch,
	}, nil
}

func (s *Server) RouteV2AuthAddCredentialFinish(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse and validate the request body
	var req v2AuthAddCredentialFinishRequest
	if c.ShouldBindJSON(&req) != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || len(req.Credential) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required fields"))
		return
	}
	req.CredentialName = strings.TrimSpace(req.CredentialName)

	// Parse the bundle signature
	attestSigEs, attestSigMl, err := parseHybridSignatures(req.AttestationSignatureEs384, req.AttestationSignatureMldsa87)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid attestationSignature: %v", err))
		return
	}

	// Extract the attestation payload
	attestPayload, err := protocolv2.ParseAttestationPayload(req.AttestationPayload)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid attestationPayload: %v", err))
		return
	}

	// Require the wrapped primary key on every add-credential
	if req.WrappedPrimaryKey == "" || len(req.WrappedPrimaryKey) > 512 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid wrappedPrimaryKey"))
		return
	}

	// Structurally validate the wrapped-anchor envelope
	err = validateWrappedAnchorEnvelope(req.WrappedAnchorKey)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid wrappedAnchorKey: %v", err))
		return
	}

	// Complete adding the credential
	// This must be executed in a transaction
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (addCredentialFinishRes, error) {
		return s.addCredentialFinish(c, tx, addCredentialFinishVals{
			userID:        userID,
			req:           &req,
			attestSigEs:   attestSigEs,
			attestSigMl:   attestSigMl,
			attestPayload: &attestPayload,
		})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Remove the challenge from the cleanup queue
	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Credential added to user",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Send response
	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

type addCredentialFinishVals struct {
	userID        string
	req           *v2AuthAddCredentialFinishRequest
	attestSigEs   []byte
	attestSigMl   []byte
	attestPayload *protocolv2.AttestationPayload
}
type addCredentialFinishRes struct{}

func (s *Server) addCredentialFinish(c *gin.Context, tx *db.DbTx, vals addCredentialFinishVals) (addCredentialFinishRes, error) {
	as := tx.AuthStore()

	// Bind the consume to the authenticated user's ID at the SQL layer so an attacker who learned a different user's challenge ID cannot consume it
	// The post-consume payload.UserID equality check below remains as defense in depth
	var payload v2AddCredentialChallengePayload
	err := as.ConsumeChallenge(c.Request.Context(), vals.req.ChallengeID, "add-credential", vals.userID, &payload)
	if errors.Is(err, db.ErrInvalidChallenge) {
		return addCredentialFinishRes{}, NewResponseError(http.StatusConflict, "Challenge is invalid or expired")
	} else if err != nil {
		return addCredentialFinishRes{}, err
	}

	if payload.UserID != vals.userID {
		return addCredentialFinishRes{}, NewResponseError(http.StatusForbidden, "Challenge does not belong to this user")
	}

	if payload.WebAuthnSession == nil {
		return addCredentialFinishRes{}, NewResponseError(http.StatusConflict, "Challenge is missing WebAuthn session data")
	}

	// Load the user
	storedUser, err := as.GetUserByID(c.Request.Context(), vals.userID)
	if err != nil {
		return addCredentialFinishRes{}, err
	}

	if storedUser == nil {
		return addCredentialFinishRes{}, NewResponseError(http.StatusNotFound, "User not found")
	}

	// The session JWT's Ready claim is a snapshot from token mint time
	// Re-check the stored user to reject accounts disabled or un-readied after the session was issued
	if storedUser.Status != "active" || !storedUser.Ready {
		return addCredentialFinishRes{}, NewResponseError(http.StatusForbidden, "User account is not active")
	}

	// Load the user record with existing credentials for the verification
	userRecord, err := loadWebAuthnUser(c.Request.Context(), as, storedUser)
	if err != nil {
		return addCredentialFinishRes{}, err
	}
	if userRecord == nil {
		return addCredentialFinishRes{}, NewResponseError(http.StatusNotFound, "User not found")
	}

	// Complete the WebAuthn registration
	cred, credJSON, err := s.finishWebAuthnRegistration(c, userRecord, vals.req.Credential, payload.WebAuthnSession)
	if err != nil {
		return addCredentialFinishRes{}, err
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)

	// Verify the attestation against the stored anchor pubkeys
	// This is what binds the new credential to the user's identity root
	anchorEs384Pub, mldsa87PubBytes, err := parseAnchorPubkeys(storedUser.AnchorEs384PublicKey, storedUser.AnchorMldsa87PublicKey)
	if err != nil {
		return addCredentialFinishRes{}, NewResponseErrorf(http.StatusInternalServerError, "stored anchor public key is invalid: %v", err)
	}

	// Derive the expected credentialPublicKeyHash from the COSE bytes that the WebAuthn library produced
	expectedCredentialPublicKeyHash, err := protocolv2.CredentialPublicKeyHash(cred.PublicKey)
	if err != nil {
		return addCredentialFinishRes{}, NewResponseErrorf(http.StatusBadRequest, "failed to derive credential public key hash: %v", err)
	}

	// Verify the hybrid attestation signature first, then compare every signed field against server-derived expected values
	// Only persist after both checks pass
	err = protocolv2.VerifyHybridAttestation(anchorEs384Pub, mldsa87PubBytes, vals.attestPayload, vals.attestSigEs, vals.attestSigMl)
	if err != nil {
		return addCredentialFinishRes{}, NewResponseErrorf(http.StatusBadRequest, "attestation signature verification failed: %v", err)
	}

	// Verify the challenge belongs to the authenticated user, and that the credential ID, publish key hash, and epoch match expectations
	if vals.attestPayload.UserID != vals.userID {
		return addCredentialFinishRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload userId does not match session")
	}
	if vals.attestPayload.CredentialID != credID {
		return addCredentialFinishRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialId does not match registered credential")
	}
	if vals.attestPayload.CredentialPublicKeyHash != expectedCredentialPublicKeyHash {
		return addCredentialFinishRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialPublicKeyHash does not match registered credential")
	}
	if vals.attestPayload.WrappedKeyEpoch != storedUser.WrappedKeyEpoch {
		return addCredentialFinishRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload wrappedKeyEpoch does not match current user epoch")
	}

	// Use the credential name from the finish request, falling back to the begin request
	credName := vals.req.CredentialName
	if credName == "" {
		credName = payload.DisplayName
	}

	err = as.AddCredential(c.Request.Context(), db.AddCredentialInput{
		UserID:                      vals.userID,
		CredentialID:                credID,
		DisplayName:                 credName,
		PublicKey:                   string(credJSON),
		SignCount:                   int64(cred.Authenticator.SignCount),
		WrappedPrimaryKey:           vals.req.WrappedPrimaryKey,
		WrappedAnchorKey:            vals.req.WrappedAnchorKey,
		AttestationPayload:          vals.req.AttestationPayload,
		AttestationSignatureEs384:   vals.req.AttestationSignatureEs384,
		AttestationSignatureMldsa87: vals.req.AttestationSignatureMldsa87,
	})
	if err != nil {
		return addCredentialFinishRes{}, err
	}

	return addCredentialFinishRes{}, nil
}

// RouteV2AuthRenameCredential is the handler for /v2/auth/credentials/rename
func (s *Server) RouteV2AuthRenameCredential(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
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

	// Rename the credential in the database
	err = s.db.AuthStore().RenameCredential(c.Request.Context(), req.ID, userID, req.DisplayName)
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

	// Send response
	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

// RouteV2AuthDeleteCredential is the handler for /v2/auth/credentials/delete
func (s *Server) RouteV2AuthDeleteCredential(c *gin.Context) {
	// Get the user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse the request body
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

	// Delete the credential from the database
	err = s.db.AuthStore().DeleteCredential(c.Request.Context(), req.ID, userID)
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

	// Send response
	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

func secureCookie(c *gin.Context) bool {
	url := location.Get(c)
	return url.Scheme == "https" || config.Get().ForceSecureCookies
}

type registerFinishRes struct {
	user *db.User
	sess *authSessionToken
}

func (s *Server) registerFinish(c *gin.Context, tx *db.DbTx, req v2AuthRegisterFinishRequest) (registerFinishRes, error) {
	as := tx.AuthStore()

	// Consume the challenge in the database and retrieve the payload
	// Register has no authenticated user yet, so the consume isn't bound to a userID
	var payload v2RegisterChallengePayload
	err := as.ConsumeChallenge(c.Request.Context(), req.ChallengeID, "register", "", &payload)
	if errors.Is(err, db.ErrInvalidChallenge) {
		return registerFinishRes{}, NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")
	} else if err != nil {
		return registerFinishRes{}, err
	}

	if payload.WebAuthnSession == nil {
		return registerFinishRes{}, NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}

	// Create the WebAuthnUser object
	displayName := payload.DisplayName
	if displayName == "" {
		displayName = payload.UserID
	}
	waUser := &v2WebAuthnUser{
		id:          payload.WebAuthnSession.UserID,
		userID:      payload.UserID,
		displayName: displayName,
	}

	// Complete the WebAuthn registration
	cred, credJSON, err := s.finishWebAuthnRegistration(c, waUser, req.Credential, payload.WebAuthnSession)
	if err != nil {
		return registerFinishRes{}, err
	}

	// Register the user in the database
	user, err := as.RegisterUser(c.Request.Context(), db.RegisterUserInput{
		UserID:         payload.UserID,
		DisplayName:    payload.DisplayName,
		WebAuthnUserID: payload.WebAuthnUserID,
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      string(credJSON),
		SignCount:      int64(cred.Authenticator.SignCount),
		SessionTTL:     config.Get().SessionTimeout,
	})
	if errors.Is(err, db.ErrUserAlreadyExists) {
		return registerFinishRes{}, NewResponseError(http.StatusConflict, "User already exists")
	} else if err != nil {
		return registerFinishRes{}, err
	}

	// Get a session token
	sess, err := newAuthSessionToken(user, config.Get().SessionTimeout)
	if err != nil {
		return registerFinishRes{}, err
	}

	return registerFinishRes{
		user: user,
		sess: sess,
	}, nil
}

type loginFinishRes struct {
	user *db.User
	sess *authSessionToken
	cred *db.AuthCredentialRecord
}

func (s *Server) loginFinish(c *gin.Context, tx *db.DbTx, req v2AuthLoginFinishRequest) (loginFinishRes, error) {
	as := tx.AuthStore()
	ctx := c.Request.Context()

	// Consume the challenge in the database and retrieve the payload
	// Login has no authenticated user yet (the credential assertion is what authenticates), so the consume isn't bound to a userID
	var payload v2LoginChallengePayload
	err := as.ConsumeChallenge(ctx, req.ChallengeID, "login", "", &payload)
	if errors.Is(err, db.ErrInvalidChallenge) {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	if payload.WebAuthnSession == nil {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is missing WebAuthn session data")
	}

	// Handler for the WebAuthn call
	// Note this is executed synchronously
	var (
		discoveredUser   *v2WebAuthnUser
		discoveredDBUser *db.User
	)
	handler := func(rawID []byte, userHandle []byte) (webauthnlib.User, error) {
		webAuthnUserID := base64.RawURLEncoding.EncodeToString(userHandle)
		user, hErr := as.GetUserByWebAuthnUserID(ctx, webAuthnUserID)
		if hErr != nil {
			return nil, hErr
		}
		if user == nil || user.Status != "active" {
			return nil, NewResponseError(http.StatusUnauthorized, "Invalid login")
		}

		userRecord, hErr := loadWebAuthnUser(ctx, as, user)
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

	// The WebAuthn requires a *http.Request object formatted with a very specific body
	waReq, err := newJSONHTTPRequest(c, req.Credential)
	if err != nil {
		return loginFinishRes{}, err
	}

	// Complete the WebAuthn login
	cred, err := s.webAuthn.FinishDiscoverableLogin(handler, *payload.WebAuthnSession, waReq)
	if err != nil {
		return loginFinishRes{}, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn login verification failed: %v", err)
	}
	if discoveredUser == nil || discoveredDBUser == nil {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	// Validate the authenticator sign count
	err = s.validateAuthenticatorSignCount(c, discoveredUser, cred)
	if err != nil {
		return loginFinishRes{}, err
	}

	// Update the sign count in the database
	credentialID := base64.RawURLEncoding.EncodeToString(cred.ID)
	err = as.Login(ctx, db.LoginInput{
		UserID:       discoveredDBUser.ID,
		CredentialID: credentialID,
		SignCount:    int64(cred.Authenticator.SignCount),
		SessionTTL:   config.Get().SessionTimeout,
	})
	if errors.Is(err, db.ErrInvalidLogin) {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	// Retrieve the credential (which was just updated)
	credRec, err := as.GetCredentialForUser(ctx, discoveredDBUser.ID, credentialID)
	if err != nil {
		return loginFinishRes{}, err
	}

	// Return the session token object
	sess, err := newAuthSessionToken(discoveredDBUser, config.Get().SessionTimeout)
	if err != nil {
		return loginFinishRes{}, err
	}

	return loginFinishRes{
		user: discoveredDBUser,
		sess: sess,
		cred: credRec,
	}, nil
}

func (s *Server) finishWebAuthnRegistration(c *gin.Context, user *v2WebAuthnUser, msg json.RawMessage, sess *webauthnlib.SessionData) (*webauthnlib.Credential, []byte, error) {
	// The WebAuthn library needs a specially-requested HTTP request, so we create one with the credential in the body
	waReq, err := newJSONHTTPRequest(c, msg)
	if err != nil {
		return nil, nil, err
	}

	// Finish the registration
	cred, err := s.webAuthn.FinishRegistration(user, *sess, waReq)
	if err != nil {
		return nil, nil, NewResponseErrorf(http.StatusUnauthorized, "WebAuthn registration verification failed: %v", err)
	}

	// Encode to JSON
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, nil, err
	}

	return cred, credJSON, nil
}

type finalizeSetupVals struct {
	userID          string
	req             *v2AuthFinalizeSignupRequest
	anchorEs384Pub  *ecdsa.PublicKey
	mldsa87PubBytes []byte
	bundleSigEs     []byte
	bundleSigMl     []byte
	attestSigEs     []byte
	attestSigMl     []byte
	attestPayload   *protocolv2.AttestationPayload
}

type finalizeSetupRes struct {
	user *db.User
}

func (s *Server) finalizeSetup(c *gin.Context, tx *db.DbTx, vals finalizeSetupVals) (finalizeSetupRes, error) {
	as := tx.AuthStore()

	// Load the user's stored credentials: at finalize-signup time the user must have exactly one credential (created by /register/finish)
	// Everything the attestation signs must be derivable from that one row
	creds, err := as.ListCredentials(c.Request.Context(), vals.userID)
	if err != nil {
		return finalizeSetupRes{}, err
	}

	if len(creds) != 1 {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusConflict, "expected exactly one credential for user at finalize-signup, got %d", len(creds))
	}

	// Get the expected pub key hash
	expectedCredentialID := creds[0].CredentialID
	expectedCredentialPublicKeyHash, err := protocolv2.CredentialPublicKeyHashFromStoredCredJSON(creds[0].PublicKey)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusInternalServerError, "failed to derive credential public key hash: %v", err)
	}

	// Bundle self-signature: the anchor signs its own wire-format representation
	// This is what the CLI verifies on every request
	es384JWK, err := protocolv2.ParseECP384PublicJWKCanonicalBody(vals.req.AnchorEs384PublicKey)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusBadRequest, "invalid anchorEs384PublicKey: %v", err)
	}

	bundlePayload := &protocolv2.PubkeyBundlePayload{
		UserID:                 vals.userID,
		RequestEncEcdhPubkey:   string(vals.req.RequestEncEcdhPubkey),
		RequestEncMlkemPubkey:  vals.req.RequestEncMlkemPubkey,
		AnchorEs384Crv:         es384JWK.Crv,
		AnchorEs384Kty:         es384JWK.Kty,
		AnchorEs384X:           es384JWK.X,
		AnchorEs384Y:           es384JWK.Y,
		AnchorMldsa87PublicKey: vals.req.AnchorMldsa87PublicKey,
		WrappedKeyEpoch:        1,
	}
	err = protocolv2.VerifyHybridBundle(vals.anchorEs384Pub, vals.mldsa87PubBytes, bundlePayload, vals.bundleSigEs, vals.bundleSigMl)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusBadRequest, "pubkey bundle signature verification failed: %v", err)
	}

	// Verify the hybrid attestation signature first, then compare every signed field against server-derived expected values
	// Only persist after both checks pass
	err = protocolv2.VerifyHybridAttestation(vals.anchorEs384Pub, vals.mldsa87PubBytes, vals.attestPayload, vals.attestSigEs, vals.attestSigMl)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusBadRequest, "attestation signature verification failed: %v", err)
	}

	if vals.attestPayload.UserID != vals.userID {
		return finalizeSetupRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload userId does not match session")
	}
	if vals.attestPayload.CredentialID != expectedCredentialID {
		return finalizeSetupRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialId does not match registered credential")
	}
	if vals.attestPayload.CredentialPublicKeyHash != expectedCredentialPublicKeyHash {
		return finalizeSetupRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialPublicKeyHash does not match registered credential")
	}
	if vals.attestPayload.WrappedKeyEpoch != 1 {
		return finalizeSetupRes{}, NewResponseError(http.StatusBadRequest, "attestationPayload wrappedKeyEpoch must be 1 at signup")
	}

	// Finalize the signup in the database
	user, err := as.FinalizeSignup(c.Request.Context(), db.FinalizeSignupInput{
		UserID:                       vals.userID,
		WrappedPrimaryKey:            vals.req.WrappedPrimaryKey,
		WrappedAnchorKey:             vals.req.WrappedAnchorKey,
		RequestEncEcdhPubkey:         string(vals.req.RequestEncEcdhPubkey),
		RequestEncMlkemPubkey:        vals.req.RequestEncMlkemPubkey,
		AnchorEs384PublicKey:         vals.req.AnchorEs384PublicKey,
		AnchorMldsa87PublicKey:       vals.req.AnchorMldsa87PublicKey,
		PubkeyBundleSignatureEs384:   vals.req.PubkeyBundleSignatureEs384,
		PubkeyBundleSignatureMldsa87: vals.req.PubkeyBundleSignatureMldsa87,
		AttestationPayload:           vals.req.AttestationPayload,
		AttestationSignatureEs384:    vals.req.AttestationSignatureEs384,
		AttestationSignatureMldsa87:  vals.req.AttestationSignatureMldsa87,
	})
	switch {
	case errors.Is(err, db.ErrAlreadyFinalized):
		return finalizeSetupRes{}, NewResponseError(http.StatusConflict, "Account is already finalized")
	case errors.Is(err, db.ErrUserNotFound):
		return finalizeSetupRes{}, NewResponseError(http.StatusNotFound, "User not found")
	case err != nil:
		return finalizeSetupRes{}, err
	}

	if user == nil || user.Status != "active" || !user.Ready {
		return finalizeSetupRes{}, noSessionResponseError
	}

	return finalizeSetupRes{
		user: user,
	}, nil
}

func (s *Server) validateAuthenticatorSignCount(c *gin.Context, userRecord *v2WebAuthnUser, cred *webauthnlib.Credential) error {
	// Detect possible cloned authenticator by comparing the returned sign count with the stored value
	// If the stored count was non-zero but the new count is not strictly greater, the credential may have been cloned
	// Note: Some authenticators do not report a counter, which is always 0
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

	// Fail-closed: if the credential that signed the assertion isn't in the user's stored credential list, refuse the login
	// This should be unreachable because FinishDiscoverableLogin already matched a stored credential
	logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
		"Authenticator credential not found in user's stored credentials",
		slog.String("user_id", userRecord.userID),
		slog.String("credential_id", credIDEncoded),
		slog.String("client_ip", c.ClientIP()),
	)
	return NewResponseError(http.StatusForbidden, "Authenticator credential not recognized")
}

// newJSONHTTPRequest returns a new http.Request with a JSON body
// This is used by the WebAuthn library as input in many instances
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

func loadWebAuthnUser(ctx context.Context, as *db.AuthStore, user *db.User) (*v2WebAuthnUser, error) {
	if user == nil || user.Status != "active" {
		return nil, nil
	}

	records, err := as.ListCredentials(ctx, user.ID)
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
				slog.String("user_id", user.ID),
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
		displayName: displayName,
		credentials: creds,
	}, nil
}

// parseAnchorPubkeys decodes the wire-format hybrid anchor public keys: a canonical-body JWK for the ES384 leg and raw base64url bytes for the ML-DSA-87 leg.
func parseAnchorPubkeys(es384JWK string, mldsa87PubBase64 string) (*ecdsa.PublicKey, []byte, error) {
	if es384JWK == "" {
		return nil, nil, errors.New("anchorEs384PublicKey is required")
	}
	if mldsa87PubBase64 == "" {
		return nil, nil, errors.New("anchorMldsa87PublicKey is required")
	}

	jwk, err := protocolv2.ParseECP384PublicJWKCanonicalBody(es384JWK)
	if err != nil {
		return nil, nil, fmt.Errorf("anchorEs384PublicKey: %w", err)
	}

	es384Pub, err := jwk.ToECDSAPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("anchorEs384PublicKey: %w", err)
	}

	mldsa87PubBytes, err := base64.RawURLEncoding.DecodeString(mldsa87PubBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("anchorMldsa87PublicKey: %w", err)
	}

	if len(mldsa87PubBytes) != protocolv2.MLDSA87PublicKeySize {
		return nil, nil, fmt.Errorf("anchorMldsa87PublicKey: expected %d bytes, got %d", protocolv2.MLDSA87PublicKeySize, len(mldsa87PubBytes))
	}

	return es384Pub, mldsa87PubBytes, nil
}

// parseHybridSignatures decodes a pair of base64url-encoded anchor signatures
// (ES384 + ML-DSA-87) and validates their lengths.
func parseHybridSignatures(es384B64, mldsa87B64 string) (sigEs, sigMl []byte, err error) {
	sigEs, err = protocolv2.DecodeBase64Signature(es384B64, protocolv2.ES384SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ES384: %w", err)
	}
	sigMl, err = protocolv2.DecodeBase64Signature(mldsa87B64, protocolv2.MLDSA87SignatureSize)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA-87: %w", err)
	}
	return sigEs, sigMl, nil
}
