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
	"uuid"

	location "github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/italypaleale/revaulter/internal/actors"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils"
	"github.com/italypaleale/revaulter/internal/utils/logging"
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
	UserID             string                 `json:"userId"`
	DisplayName        string                 `json:"displayName"`
	RequestKey         string                 `json:"requestKey"`
	RequestKeyEnabled  bool                   `json:"requestKeyEnabled"`
	RequestOIDCEnabled bool                   `json:"requestOidcEnabled"`
	RequestOIDCIssuers []db.RequestOIDCIssuer `json:"requestOidcIssuers"`
	AnchorFingerprint  string                 `json:"anchorFingerprint"`
	WrappedKeyEpoch    int64                  `json:"wrappedKeyEpoch"`
	AllowedIPs         []string               `json:"allowedIps"`
	TTL                int                    `json:"ttl"`
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
	PubkeyBundleVersion          int64  `json:"pubkeyBundleVersion"`

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

// attestationCreatedAtSkew bounds how far the signed attestation `createdAt` may drift from server now
// Pinning to ±2 minutes blocks replay of a captured attestation that lingered before submission while still tolerating modest client clock skew
const attestationCreatedAtSkew = 2 * time.Minute

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
	userID := uuid.NewV4().String()
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

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	expiresAt := challengeExpiry(session)

	// Store the signup in its revaulter.signup actor, which holds it until it's finalized
	// The actor is keyed by the WebAuthn user handle, which the browser sends back as the challenge ID, and which identifies the user at sign-in before the signup is finalized
	signupID := base64.RawURLEncoding.EncodeToString(user.id)
	err = s.actors.Signup(signupID).Begin(c.Request.Context(), actors.Signup{
		UserID:         userID,
		DisplayName:    req.DisplayName,
		WebAuthnUserID: signupID,
		Session:        sessionJSON,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthRegisterBeginResponse{
		ChallengeID: signupID,
		Challenge:   session.Challenge,
		ExpiresAt:   expiresAt.Unix(),
		Mode:        "webauthn",
		Options:     creation,
		BasePrfSalt: cfg.GetPRFSalt(),
	})
}

// challengeExpiry returns when a WebAuthn ceremony expires
func challengeExpiry(session *webauthnlib.SessionData) time.Time {
	if session == nil || session.Expires.IsZero() {
		return time.Now().Add(5 * time.Minute)
	}
	return session.Expires
}

func (s *Server) beginWebAuthnSession(user *v2WebAuthnUser) (creation *protocol.CredentialCreation, session *webauthnlib.SessionData, err error) {
	// Begin the WebAuthn registration session
	return s.webAuthn.BeginRegistration(user,
		// We require discoverable credentials aka Passkeys
		webauthnlib.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		// Add PRF extension
		webauthnlib.WithExtensions(webauthnlib.WithExtensionPRFSupport()),
		// Offer post-quantum credential algorithms alongside the classical ones
		webauthnlib.WithCredentialParameters(credentialParameters()),
	)
}

// credentialParameters returns the credential algorithms offered during registration, in order of preference
// It is the library's default list with the ML-DSA parameter sets in front, so an authenticator that implements a post-quantum algorithm produces a post-quantum credential while every classical algorithm stays available for the ones that don't
func credentialParameters() []protocol.CredentialParameter {
	defaults := webauthnlib.CredentialParametersDefault()
	params := make([]protocol.CredentialParameter, 0, len(defaults)+3)

	// FIPS 204 parameter sets registered for WebAuthn credentials
	params = append(params,
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA44,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA65,
		},
		protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA87,
		},
	)

	// Add the defaults at the end
	return append(params, defaults...)
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
	// The user stays in the revaulter.signup actor until the signup is finalized, and it's removed if that doesn't happen in time
	res, err := s.registerFinish(c, req)
	if err != nil {
		logging.
			LogFromContext(c.Request.Context()).
			WarnContext(c.Request.Context(), "User registration failed",
				slog.String("client_ip", c.ClientIP()),
			)

		// The success row is written only when the registration is stored, so record the failure separately
		s.auditEvent(c, auditFields{
			EventType:  db.AuditAuthRegisterFinish,
			Outcome:    db.AuditOutcomeFailure,
			AuthMethod: db.AuditAuthMethodNone,
		})

		AbortWithErrorJSON(c, err)
		return
	}

	// Set the session cookie
	err = setSessionCookie(c, res.sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.
		LogFromContext(c.Request.Context()).
		InfoContext(c.Request.Context(), "User registered",
			slog.String("user_id", res.signup.UserID),
			slog.String("client_ip", c.ClientIP()),
		)

	// Respond
	c.JSON(http.StatusOK, v2AuthRegisterFinishResponse{
		Registered: true,
		Session:    sessionInfoFromSignup(res.signup, int(max(time.Until(res.sess.ExpiresAt), 0).Seconds())),
	})
}

// RouteV2AuthLoginBegin is the handler for POST /v2/auth/login/begin
func (s *Server) RouteV2AuthLoginBegin(c *gin.Context) {
	// Get an assertion and store it in the database
	assertion, session, err := s.webAuthn.BeginDiscoverableLogin(
		webauthnlib.WithAssertionExtensions(webauthnlib.WithExtensionPRFSupport()),
	)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	payload, err := json.Marshal(v2LoginChallengePayload{
		Challenge:       session.Challenge,
		WebAuthnSession: session,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Store the challenge in its revaulter.challenge actor, which deletes it once it expires
	expiresAt := challengeExpiry(session)
	challengeID, err := s.actors.BeginChallenge(c.Request.Context(), actors.ChallengeKindLogin, "", expiresAt, payload)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusOK, v2AuthLoginBeginResponse{
		ChallengeID: challengeID,
		Challenge:   session.Challenge,
		ExpiresAt:   expiresAt.Unix(),
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
	res, err := s.loginFinish(c, req)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Login failed",
			slog.String("client_ip", c.ClientIP()),
		)

		// The success row is written only when the login is recorded, so record the failure separately
		s.auditEvent(c, auditFields{
			EventType:  db.AuditAuthLoginFinish,
			Outcome:    db.AuditOutcomeFailure,
			AuthMethod: db.AuditAuthMethodNone,
		})

		AbortWithErrorJSON(c, err)
		return
	}

	// Create the response object
	ttl := int(max(time.Until(res.sess.ExpiresAt), 0).Seconds())
	resp := v2AuthLoginFinishResponse{
		Authenticated: true,
	}
	if res.user != nil {
		resp.Session = sessionInfoFromUser(res.user, ttl)
	} else {
		resp.Session = sessionInfoFromSignup(res.signup, ttl)
	}

	// Throttle wrapped primary key delivery
	// The wrapped primary key is the user's encrypted root-key material:
	// an attacker that controls a passkey could otherwise call /v2/auth/login/finish in a tight loop and harvest the blob for offline password cracking
	// We refuse the login so the client cannot abuse this endpoint
	logMsg := "User logged in"
	if res.cred != nil && res.cred.WrappedPrimaryKey != "" {
		resp.CredentialWrappedKeyEpoch = res.cred.WrappedKeyEpoch
		resp.WrappedKeyStale = res.cred.WrappedKeyEpoch > 0 && res.cred.WrappedKeyEpoch < res.user.WrappedKeyEpoch
		allowed, retryAfter := s.wrappedKeyLimiter.Allow(c.Request.Context(), res.user.ID)
		if !allowed {
			// A WebAuthn-authenticated client that exceeds the budget has a 429 returned
			logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
				"Refused wrapped-key delivery: per-user rate limit exceeded",
				slog.String("user_id", res.user.ID),
				slog.String("client_ip", c.ClientIP()),
			)

			setRetryAfter(c, retryAfter)
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
		slog.String("user_id", res.sess.UserID),
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

	// Sessions of users that finalized their signup carry no signup ID
	signupID := c.GetString(contextKeySignupID)
	if signupID == "" {
		AbortWithErrorJSON(c, alreadyFinalizedResponseError)
		return
	}

	// Verify the material and create the user
	res, err := s.finalizeSetup(c, finalizeSetupVals{
		userID:          userID,
		signupID:        signupID,
		req:             &req,
		anchorEs384Pub:  anchorEs384Pub,
		mldsa87PubBytes: mldsa87PubBytes,
		bundleSigEs:     bundleSigEs,
		bundleSigMl:     bundleSigMl,
		attestSigEs:     attestSigEs,
		attestSigMl:     attestSigMl,
		attestPayload:   &attestPayload,
	})
	if err != nil {
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

	// Update the IPs and write the audit row atomically
	allowedIPs, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) ([]string, error) {
		ips, rErr := tx.AuthStore().UpdateAllowedIPs(ctx, userID, req.AllowedIPs)
		if rErr != nil {
			return nil, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthAllowedIPsChange,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			Metadata: jsonMetadata(map[string]any{
				"newCount": len(ips),
				"oldCount": len(req.AllowedIPs),
			}),
		})
		if rErr != nil {
			return nil, rErr
		}

		return ips, nil
	})
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

	// Rotate the request key and write the audit row atomically
	requestKey, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (string, error) {
		key, rErr := tx.AuthStore().RegenerateRequestKey(ctx, userID)
		if rErr != nil {
			return "", rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthRequestKeyRegen,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
		})
		if rErr != nil {
			return "", rErr
		}

		return key, nil
	})
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
// This is acceptable since most session tokens have a very short lifetime anyways
func (s *Server) RouteV2AuthLogout(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "User logged out",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Save the event in the audit log
	s.auditEvent(c, auditFields{
		EventType:    db.AuditAuthLogout,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		TargetUserID: userID,
	})

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

	// Update the name and write the audit row atomically
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.AuthStore().UpdateDisplayName(ctx, userID, req.DisplayName)
		if rErr != nil {
			return struct{}{}, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthDisplayNameChange,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
		})
		if rErr != nil {
			return struct{}{}, rErr
		}

		return struct{}{}, nil
	})
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
		return struct{}{}, s.updateWrappedKey(c, tx, userID, &req)
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

func (s *Server) updateWrappedKey(c *gin.Context, tx *db.DbTx, userID string, req *v2AuthUpdateWrappedKeyRequest) error {
	ctx := c.Request.Context()
	as := tx.AuthStore()

	// Lock the user until the transaction ends, so adding a passkey can't interleave with the password change
	lockedUser, err := as.GetUserByIDForUpdate(ctx, userID)
	if err != nil {
		return NewResponseError(http.StatusInternalServerError, "Failed to load user")
	}
	if lockedUser == nil {
		return NewResponseError(http.StatusNotFound, "User not found")
	}

	// Refuse the update while an add-credential WebAuthn ceremony is in flight for this user
	// The in-flight ceremony will wrap the new credential's primary key with the current password, and letting the password change land in between would leave that new credential wrapped with the old password while the signed-in credential picks up the new one
	pending, err := s.actors.HasPendingAddCredentialChallenge(ctx, userID)
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
	switch {
	case errors.Is(err, db.ErrCredentialNotFound):
		return NewResponseError(http.StatusNotFound, "Credential not found")
	case errors.Is(err, db.ErrWrappedKeyTooLarge):
		return NewResponseError(http.StatusBadRequest, err.Error())
	case err != nil:
		return fmt.Errorf("failed to update the wrapped key: %w", err)
	}

	// Save the audit log entry
	err = s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthWrappedKeyUpdate,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		TargetUserID: userID,
		CredentialID: req.CredentialID,
		Metadata: jsonMetadata(map[string]any{
			"advanceEpoch": req.AdvanceEpoch,
		}),
	})
	if err != nil {
		return err
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

	// Begin the ceremony
	res, err := s.addCredentialBegin(c.Request.Context(), userID, &req)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send response
	c.JSON(http.StatusOK, v2AuthAddCredentialBeginResponse{
		ChallengeID: res.challengeID,
		Challenge:   res.session.Challenge,
		ExpiresAt:   res.expiresAt.Unix(),
		Options:     credentialCreationWithoutExclusions(res.creation),
		BasePrfSalt: config.Get().GetPRFSalt(),
	})
}

type addCredentialBeginRes struct {
	creation    *protocol.CredentialCreation
	session     *webauthnlib.SessionData
	challengeID string
	expiresAt   time.Time
}

func credentialCreationWithoutExclusions(creation *protocol.CredentialCreation) any {
	if creation == nil {
		return nil
	}

	// Copy the top-level creation options so the WebAuthn session stored in the challenge still keeps its original exclusion list
	// This is intentionally shallow because we only replace the excludeCredentials slice header on the response sent to the browser
	// Keeping excludeCredentials out of the add-passkey browser ceremony avoids browsers rejecting the request when another provider already has an existing passkey (e.g. Chromium-based ones)
	// Duplicate credential IDs are still rejected server-side when the add-passkey finish request is verified
	copy := *creation
	copy.Response.CredentialExcludeList = nil
	return &copy
}

func (s *Server) addCredentialBegin(ctx context.Context, userID string, req *v2AuthAddCredentialBeginRequest) (addCredentialBeginRes, error) {
	as := s.db.AuthStore()

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

	payload, err := json.Marshal(v2AddCredentialChallengePayload{
		UserID:          userID,
		WebAuthnUserID:  base64.RawURLEncoding.EncodeToString(userRecord.id),
		DisplayName:     strings.TrimSpace(req.CredentialName),
		WebAuthnSession: session,
	})
	if err != nil {
		return addCredentialBeginRes{}, err
	}

	// Store the challenge in the revaulter.challenge actor of the user, replacing any previous one
	expiresAt := challengeExpiry(session)
	challengeID, err := s.actors.BeginChallenge(ctx, actors.ChallengeKindAddCredential, userID, expiresAt, payload)
	if err != nil {
		return addCredentialBeginRes{}, err
	}

	return addCredentialBeginRes{
		creation:    creation,
		session:     session,
		challengeID: challengeID,
		expiresAt:   expiresAt,
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

	// Consume the challenge, which is bound to the authenticated user, so an attacker who learned a different user's challenge ID cannot consume it
	// The challenge can be used once only, even if adding the credential fails
	payloadJSON, err := s.actors.ConsumeChallenge(c.Request.Context(), actors.ChallengeKindAddCredential, req.ChallengeID, userID)
	if errors.Is(err, actors.ErrInvalidChallenge) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Challenge is invalid or expired"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	var payload v2AddCredentialChallengePayload
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Challenge is missing WebAuthn session data"))
		return
	}

	// Complete adding the credential
	// This must be executed in a transaction
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (addCredentialFinishRes, error) {
		return s.addCredentialFinish(c, tx, addCredentialFinishVals{
			userID:        userID,
			req:           &req,
			payload:       &payload,
			attestSigEs:   attestSigEs,
			attestSigMl:   attestSigMl,
			attestPayload: &attestPayload,
		})
	})
	if err != nil {
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
	payload       *v2AddCredentialChallengePayload
	attestSigEs   []byte
	attestSigMl   []byte
	attestPayload *protocolv2.AttestationPayload
}
type addCredentialFinishRes struct{}

func (s *Server) addCredentialFinish(c *gin.Context, tx *db.DbTx, vals addCredentialFinishVals) (addCredentialFinishRes, error) {
	as := tx.AuthStore()

	// The challenge is bound to the authenticated user already, so this check is defense in depth
	payload := vals.payload
	if payload.UserID != vals.userID {
		return addCredentialFinishRes{}, NewResponseError(http.StatusForbidden, "Challenge does not belong to this user")
	}

	if payload.WebAuthnSession == nil {
		return addCredentialFinishRes{}, NewResponseError(http.StatusConflict, "Challenge is missing WebAuthn session data")
	}

	// Load the user, and lock it until the transaction ends
	// A password change takes the same lock, so it can't change the wrapped key epoch between the checks below and the insert
	storedUser, err := as.GetUserByIDForUpdate(c.Request.Context(), vals.userID)
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
	err = requirePRFSupport(cred)
	if err != nil {
		return addCredentialFinishRes{}, err
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)

	// Retrieve the list of existing credentials to make sure that the same one isn't already registered
	existingCredential, err := as.GetCredentialByCredentialID(c.Request.Context(), credID, vals.userID)
	if err != nil {
		return addCredentialFinishRes{}, err
	}
	if existingCredential != nil {
		return addCredentialFinishRes{}, NewResponseError(http.StatusConflict, "Credential is already registered")
	}

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

	// Pin the signed createdAt to a ±2 minute window of server now so an old captured attestation cannot be replayed
	err = vals.attestPayload.ValidateCreatedAt(time.Now(), attestationCreatedAtSkew)
	if err != nil {
		return addCredentialFinishRes{}, NewResponseErrorf(http.StatusBadRequest, "attestationPayload %v", err)
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
		WrappedKeyEpoch:             storedUser.WrappedKeyEpoch,
	})
	if errors.Is(err, db.ErrWrappedKeyEpochChanged) {
		return addCredentialFinishRes{}, NewResponseError(http.StatusConflict, "The password changed while the passkey was being added, try again")
	} else if err != nil {
		return addCredentialFinishRes{}, err
	}

	// Save the audit log entry
	err = s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthCredentialAdd,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  vals.userID,
		TargetUserID: vals.userID,
		CredentialID: credID,
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

	// Rename and write the audit row atomically
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.AuthStore().RenameCredential(ctx, req.ID, userID, req.DisplayName)
		if rErr != nil {
			return struct{}{}, rErr
		}
		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthCredentialRename,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			CredentialID: req.ID,
		})
		return struct{}{}, rErr
	})
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

	// Delete and write the audit row atomically
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.AuthStore().DeleteCredential(ctx, req.ID, userID)
		if rErr != nil {
			return struct{}{}, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthCredentialDelete,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			CredentialID: req.ID,
		})
		if rErr != nil {
			return struct{}{}, rErr
		}

		return struct{}{}, nil
	})
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
	signup *actors.Signup
	sess   *authSessionToken
}

//nolint:errname
var invalidRegistrationChallengeResponseError = NewResponseError(http.StatusConflict, "Registration challenge is invalid or expired")

func (s *Server) registerFinish(c *gin.Context, req v2AuthRegisterFinishRequest) (registerFinishRes, error) {
	ctx := c.Request.Context()

	// Load the signup, whose ID is the challenge ID returned by register/begin
	signupClient := s.actors.Signup(req.ChallengeID)
	signup, err := signupClient.Get(ctx)
	if err != nil {
		return registerFinishRes{}, err
	}
	if signup == nil || signup.Phase != actors.SignupPhaseBegun {
		return registerFinishRes{}, invalidRegistrationChallengeResponseError
	}

	var session webauthnlib.SessionData
	err = json.Unmarshal(signup.Session, &session)
	if err != nil {
		return registerFinishRes{}, NewResponseError(http.StatusConflict, "Registration challenge is missing WebAuthn session data")
	}

	// Create the WebAuthnUser object
	displayName := signup.DisplayName
	if displayName == "" {
		displayName = signup.UserID
	}
	waUser := &v2WebAuthnUser{
		id:          session.UserID,
		userID:      signup.UserID,
		displayName: displayName,
	}

	// Complete the WebAuthn registration
	cred, credJSON, err := s.finishWebAuthnRegistration(c, waUser, req.Credential, &session)
	if err != nil {
		return registerFinishRes{}, err
	}
	err = requirePRFSupport(cred)
	if err != nil {
		return registerFinishRes{}, err
	}

	// Store the passkey in the signup, together with the audit log entry
	// The actor accepts it only while the signup is begun, so a registration challenge can be used once only
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthRegisterFinish,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  signup.UserID,
		TargetUserID: signup.UserID,
	})
	signup, err = signupClient.Register(ctx, actors.SignupCredential{
		ID:        base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey: string(credJSON),
		SignCount: int64(cred.Authenticator.SignCount),
	}, &audit)
	if errors.Is(err, actors.ErrSignupNotFound) {
		return registerFinishRes{}, invalidRegistrationChallengeResponseError
	} else if err != nil {
		return registerFinishRes{}, err
	}

	return registerFinishRes{
		signup: signup,
		sess:   newSignupSessionToken(signup, config.Get().SessionTimeout),
	}, nil
}

type loginFinishRes struct {
	// User that signed in, or nil if the user hasn't finalized their signup yet
	user *db.User
	// Signup of the user that signed in, if the user hasn't finalized it yet
	signup *actors.Signup
	sess   *authSessionToken
	cred   *db.AuthCredentialRecord
}

//nolint:errname
var invalidLoginResponseError = NewResponseError(http.StatusUnauthorized, "Invalid login")

func (s *Server) loginFinish(c *gin.Context, req v2AuthLoginFinishRequest) (loginFinishRes, error) {
	as := s.db.AuthStore()
	ctx := c.Request.Context()

	// Consume the challenge and retrieve the payload, so the challenge can be used once only
	// Login has no authenticated user yet (the credential assertion is what authenticates), so the challenge isn't bound to a user
	payloadJSON, err := s.actors.ConsumeChallenge(ctx, actors.ChallengeKindLogin, req.ChallengeID, "")
	if errors.Is(err, actors.ErrInvalidChallenge) {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	var payload v2LoginChallengePayload
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil || payload.WebAuthnSession == nil {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is missing WebAuthn session data")
	}

	// Handler for the WebAuthn call
	// Note this is executed synchronously
	var (
		discoveredUser   *v2WebAuthnUser
		discoveredDBUser *db.User
		discoveredSignup *actors.Signup
	)
	handler := func(rawID []byte, userHandle []byte) (webauthnlib.User, error) {
		webAuthnUserID := base64.RawURLEncoding.EncodeToString(userHandle)
		user, hErr := as.GetUserByWebAuthnUserID(ctx, webAuthnUserID)
		if hErr != nil {
			return nil, hErr
		}

		// Users that haven't finalized their signup are in the revaulter.signup actor, which is keyed by the user handle
		if user == nil {
			signup, hErr := s.actors.Signup(webAuthnUserID).Get(ctx)
			if hErr != nil {
				return nil, hErr
			}

			userRecord := webAuthnUserFromSignup(ctx, signup)
			if userRecord == nil {
				return nil, invalidLoginResponseError
			}

			discoveredSignup = signup
			discoveredUser = userRecord

			return userRecord, nil
		}

		if user.Status != "active" {
			return nil, invalidLoginResponseError
		}

		userRecord, hErr := loadWebAuthnUser(ctx, as, user)
		if hErr != nil {
			return nil, hErr
		}
		if userRecord == nil {
			return nil, invalidLoginResponseError
		}

		discoveredDBUser = user
		discoveredUser = userRecord

		return userRecord, nil
	}

	// Discard the PRF output that older clients may still send, so it never reaches the WebAuthn library
	credential, err := stripWebAuthnPRFResults(req.Credential)
	if err != nil {
		return loginFinishRes{}, NewResponseError(http.StatusBadRequest, "Invalid WebAuthn credential")
	}

	// The WebAuthn requires a *http.Request object formatted with a very specific body
	waReq, err := newJSONHTTPRequest(c, credential)
	if err != nil {
		return loginFinishRes{}, err
	}

	// Complete the WebAuthn login
	// The library's error says why verification failed, which would help an attacker probing with a stolen assertion, so it's only logged
	cred, err := s.webAuthn.FinishDiscoverableLogin(handler, *payload.WebAuthnSession, waReq)
	if err != nil {
		logWebAuthnError(ctx, "login", err)
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Passkey verification failed")
	}
	if discoveredUser == nil || (discoveredDBUser == nil && discoveredSignup == nil) {
		return loginFinishRes{}, invalidLoginResponseError
	}

	// Reject counter anomalies early, before the database or signup actor checks the current counter atomically
	err = s.validateAuthenticatorSignCount(c, discoveredUser, cred)
	if err != nil {
		return loginFinishRes{}, err
	}

	credentialID := base64.RawURLEncoding.EncodeToString(cred.ID)
	signCount := int64(cred.Authenticator.SignCount)

	if discoveredSignup != nil {
		return s.loginFinishSignup(c, discoveredSignup, credentialID, signCount)
	}

	// Update the sign count and write the audit log entry atomically
	return db.ExecuteInTransaction(ctx, s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (loginFinishRes, error) {
		txAs := tx.AuthStore()
		rErr := txAs.Login(ctx, db.LoginInput{
			UserID:       discoveredDBUser.ID,
			CredentialID: credentialID,
			SignCount:    signCount,
			SessionTTL:   config.Get().SessionTimeout,
		})
		if errors.Is(rErr, db.ErrInvalidLogin) {
			return loginFinishRes{}, invalidLoginResponseError
		} else if rErr != nil {
			return loginFinishRes{}, rErr
		}

		// Retrieve the credential (which was just updated)
		credRec, rErr := txAs.GetCredentialForUser(ctx, discoveredDBUser.ID, credentialID)
		if rErr != nil {
			return loginFinishRes{}, rErr
		}

		// Return the session token object
		sess, rErr := newAuthSessionToken(discoveredDBUser, config.Get().SessionTimeout)
		if rErr != nil {
			return loginFinishRes{}, rErr
		}

		// Save the audit log entry
		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthLoginFinish,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  discoveredDBUser.ID,
			TargetUserID: discoveredDBUser.ID,
			CredentialID: credentialID,
		})
		if rErr != nil {
			return loginFinishRes{}, rErr
		}

		return loginFinishRes{
			user: discoveredDBUser,
			sess: sess,
			cred: credRec,
		}, nil
	})
}

// loginFinishSignup records a sign-in of a user that hasn't finalized their signup yet
func (s *Server) loginFinishSignup(c *gin.Context, signup *actors.Signup, credentialID string, signCount int64) (loginFinishRes, error) {
	// Update the sign count in the signup, together with the audit log entry
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthLoginFinish,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  signup.UserID,
		TargetUserID: signup.UserID,
		CredentialID: credentialID,
	})
	signup, err := s.actors.Signup(signup.WebAuthnUserID).Login(c.Request.Context(), credentialID, signCount, &audit)
	if errors.Is(err, actors.ErrSignupNotFound) || errors.Is(err, db.ErrInvalidLogin) {
		return loginFinishRes{}, invalidLoginResponseError
	} else if err != nil {
		return loginFinishRes{}, err
	}

	return loginFinishRes{
		signup: signup,
		sess:   newSignupSessionToken(signup, config.Get().SessionTimeout),
	}, nil
}

func (s *Server) finishWebAuthnRegistration(c *gin.Context, user *v2WebAuthnUser, msg json.RawMessage, sess *webauthnlib.SessionData) (*webauthnlib.Credential, []byte, error) {
	// Registration does not evaluate the PRF, but discard any PRF output defensively, as on login
	credential, err := stripWebAuthnPRFResults(msg)
	if err != nil {
		return nil, nil, NewResponseError(http.StatusBadRequest, "Invalid WebAuthn credential")
	}

	// The WebAuthn library needs a specially-requested HTTP request, so we create one with the credential in the body
	waReq, err := newJSONHTTPRequest(c, credential)
	if err != nil {
		return nil, nil, err
	}

	// Finish the registration
	// As with login, the library's error is only logged
	cred, err := s.webAuthn.FinishRegistration(user, *sess, waReq)
	if err != nil {
		logWebAuthnError(c.Request.Context(), "registration", err)
		return nil, nil, NewResponseError(http.StatusUnauthorized, "Passkey registration failed")
	}

	// Encode to JSON
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, nil, err
	}

	return cred, credJSON, nil
}

func requirePRFSupport(cred *webauthnlib.Credential) error {
	if cred == nil || cred.Extensions.PRFEnabled == nil || !*cred.Extensions.PRFEnabled {
		return NewResponseError(http.StatusBadRequest, "Passkey does not support the required PRF extension")
	}
	return nil
}

type finalizeSetupVals struct {
	userID          string
	signupID        string
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

//nolint:errname
var alreadyFinalizedResponseError = NewResponseError(http.StatusConflict, "Account is already finalized")

func (s *Server) finalizeSetup(c *gin.Context, vals finalizeSetupVals) (finalizeSetupRes, error) {
	ctx := c.Request.Context()

	// Load the signup, which holds the passkey created by /register/finish
	// Everything the attestation signs must be derivable from that passkey
	signupClient := s.actors.Signup(vals.signupID)
	signup, err := signupClient.Get(ctx)
	if err != nil {
		return finalizeSetupRes{}, err
	}
	if signup == nil || signup.Phase != actors.SignupPhaseRegistered || signup.Credential == nil || signup.UserID != vals.userID {
		// The signup may have been finalized by a previous call
		user, gErr := s.db.AuthStore().GetUserByID(ctx, vals.userID)
		if gErr != nil {
			return finalizeSetupRes{}, gErr
		}
		if user != nil {
			return finalizeSetupRes{}, alreadyFinalizedResponseError
		}
		return finalizeSetupRes{}, NewResponseError(http.StatusNotFound, "User not found")
	}

	// Get the expected pub key hash
	expectedCredentialID := signup.Credential.ID
	expectedCredentialPublicKeyHash, err := protocolv2.CredentialPublicKeyHashFromStoredCredJSON(signup.Credential.PublicKey)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusInternalServerError, "failed to derive credential public key hash: %v", err)
	}

	// Bundle self-signature: the anchor signs its own wire-format representation
	// This is what the CLI verifies on every request
	bundleVersion, err := verifySignupPubkeyBundle(vals)
	if err != nil {
		return finalizeSetupRes{}, err
	}

	// Verify the hybrid attestation signature first, then compare every signed field against server-derived expected values
	// Only persist after both checks pass
	err = protocolv2.VerifyHybridAttestation(vals.anchorEs384Pub, vals.mldsa87PubBytes, vals.attestPayload, vals.attestSigEs, vals.attestSigMl)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusBadRequest, "attestation signature verification failed: %v", err)
	}

	// Pin the signed createdAt to a ±2 minute window of server now so an old captured attestation cannot be replayed
	err = vals.attestPayload.ValidateCreatedAt(time.Now(), attestationCreatedAtSkew)
	if err != nil {
		return finalizeSetupRes{}, NewResponseErrorf(http.StatusBadRequest, "attestationPayload %v", err)
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

	// Create the user in the database, with all the material generated at signup and the audit log entry
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthFinalizeSignup,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  vals.userID,
		TargetUserID: vals.userID,
	})
	_, err = signupClient.Finalize(ctx, db.FinalizeSignupInput{
		UserID:                       vals.userID,
		WrappedPrimaryKey:            vals.req.WrappedPrimaryKey,
		WrappedAnchorKey:             vals.req.WrappedAnchorKey,
		RequestEncEcdhPubkey:         string(vals.req.RequestEncEcdhPubkey),
		RequestEncMlkemPubkey:        vals.req.RequestEncMlkemPubkey,
		AnchorEs384PublicKey:         vals.req.AnchorEs384PublicKey,
		AnchorMldsa87PublicKey:       vals.req.AnchorMldsa87PublicKey,
		PubkeyBundleSignatureEs384:   vals.req.PubkeyBundleSignatureEs384,
		PubkeyBundleSignatureMldsa87: vals.req.PubkeyBundleSignatureMldsa87,
		PubkeyBundleVersion:          bundleVersion,
		AttestationPayload:           vals.req.AttestationPayload,
		AttestationSignatureEs384:    vals.req.AttestationSignatureEs384,
		AttestationSignatureMldsa87:  vals.req.AttestationSignatureMldsa87,
	}, &audit)
	switch {
	case errors.Is(err, actors.ErrSignupAlreadyFinalized):
		return finalizeSetupRes{}, alreadyFinalizedResponseError
	case errors.Is(err, actors.ErrSignupNotFound):
		return finalizeSetupRes{}, NewResponseError(http.StatusNotFound, "User not found")
	case err != nil:
		return finalizeSetupRes{}, err
	}

	// Load the new user
	user, err := s.db.AuthStore().GetUserByID(ctx, vals.userID)
	if err != nil {
		return finalizeSetupRes{}, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return finalizeSetupRes{}, noSessionResponseError
	}

	return finalizeSetupRes{
		user: user,
	}, nil
}

// verifySignupPubkeyBundle reconstructs the canonical pubkey-bundle payload for the version requested at signup and verifies both hybrid signature legs
// Returns the normalized version (an omitted version means the legacy v1 payload) that must be stored alongside the signatures, so verifiers can later rebuild the exact signed bytes
func verifySignupPubkeyBundle(vals finalizeSetupVals) (int64, error) {
	es384JWK, err := protocolv2.ParseECP384PublicJWKCanonicalBody(vals.req.AnchorEs384PublicKey)
	if err != nil {
		return 0, NewResponseErrorf(http.StatusBadRequest, "invalid anchorEs384PublicKey: %v", err)
	}

	// If the client did not provide a bundle version, assume legacy version 1
	version := vals.req.PubkeyBundleVersion
	if version == 0 {
		version = protocolv2.PubkeyBundleVersion1
	}

	switch version {
	case protocolv2.PubkeyBundleVersion1:
		// Legacy payload: binds the wrapped-key epoch, which is always 1 at signup and stays 1 in the signed bytes forever (the live epoch advances on password changes but the bundle is never re-signed)
		bundlePayload := &protocolv2.PubkeyBundlePayload{
			UserID:                 vals.userID,
			RequestEncEcdhPubkey:   string(vals.req.RequestEncEcdhPubkey),
			RequestEncMlkemPubkey:  vals.req.RequestEncMlkemPubkey,
			AnchorEs384Crv:         es384JWK.Crv,
			AnchorEs384Kty:         es384JWK.Kty,
			AnchorEs384X:           es384JWK.X,
			AnchorEs384Y:           es384JWK.Y,
			AnchorMldsa87PublicKey: vals.req.AnchorMldsa87PublicKey,
			WrappedKeyEpoch:        protocolv2.PubkeyBundleWrappedKeyEpoch,
		}
		err = protocolv2.VerifyHybridBundle(vals.anchorEs384Pub, vals.mldsa87PubBytes, bundlePayload, vals.bundleSigEs, vals.bundleSigMl)
	case protocolv2.PubkeyBundleVersion2:
		bundlePayload := &protocolv2.PubkeyBundlePayloadV2{
			UserID:                 vals.userID,
			RequestEncEcdhPubkey:   string(vals.req.RequestEncEcdhPubkey),
			RequestEncMlkemPubkey:  vals.req.RequestEncMlkemPubkey,
			AnchorEs384Crv:         es384JWK.Crv,
			AnchorEs384Kty:         es384JWK.Kty,
			AnchorEs384X:           es384JWK.X,
			AnchorEs384Y:           es384JWK.Y,
			AnchorMldsa87PublicKey: vals.req.AnchorMldsa87PublicKey,
			V:                      protocolv2.PubkeyBundleVersion2,
		}
		err = protocolv2.VerifyHybridBundleV2(vals.anchorEs384Pub, vals.mldsa87PubBytes, bundlePayload, vals.bundleSigEs, vals.bundleSigMl)
	default:
		return 0, NewResponseErrorf(http.StatusBadRequest, "unsupported pubkeyBundleVersion %d", version)
	}
	if err != nil {
		return 0, NewResponseErrorf(http.StatusBadRequest, "pubkey bundle signature verification failed: %v", err)
	}

	return version, nil
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

// logWebAuthnError logs concise structured details for a failed WebAuthn ceremony
func logWebAuthnError(ctx context.Context, ceremony string, err error) {
	attrs := []any{
		slog.String("ceremony", ceremony),
		slog.String("error", err.Error()),
	}

	pErr, ok := errors.AsType[*protocol.Error](err)
	if ok {
		attrs = append(attrs,
			slog.String("webauthn_error_type", pErr.Type),
			slog.String("webauthn_error_details", pErr.Details),
		)
	}

	logging.LogFromContext(ctx).WarnContext(ctx, "WebAuthn ceremony failed", attrs...)
}

// stripWebAuthnPRFResults removes clientExtensionResults.prf.results from a browser credential
// The PRF output is the secret that wraps the user's primary key, so the server must not process it even when an older client still sends it
// go-webauthn only reads prf.enabled from the extension outputs, so removing the results does not affect verification
// Members that are not removed are passed through unchanged
func stripWebAuthnPRFResults(credential json.RawMessage) (json.RawMessage, error) {
	var root map[string]json.RawMessage
	err := json.Unmarshal(credential, &root)
	if err != nil {
		return nil, fmt.Errorf("credential must be a JSON object: %w", err)
	}

	// A missing member at any level means there is no PRF output to remove
	// A JSON null decodes to a nil map, which behaves the same as a missing member
	rawExtensions, ok := root["clientExtensionResults"]
	if !ok {
		return credential, nil
	}

	var extensions map[string]json.RawMessage
	err = json.Unmarshal(rawExtensions, &extensions)
	if err != nil {
		return nil, fmt.Errorf("clientExtensionResults must be an object: %w", err)
	}

	rawPRF, ok := extensions["prf"]
	if !ok {
		return credential, nil
	}

	var prf map[string]json.RawMessage
	err = json.Unmarshal(rawPRF, &prf)
	if err != nil {
		return nil, fmt.Errorf("clientExtensionResults.prf must be an object: %w", err)
	}

	_, ok = prf["results"]
	if !ok {
		return credential, nil
	}

	delete(prf, "results")

	extensions["prf"], err = json.Marshal(prf)
	if err != nil {
		return nil, err
	}
	root["clientExtensionResults"], err = json.Marshal(extensions)
	if err != nil {
		return nil, err
	}

	return json.Marshal(root)
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
		cred, ok := decodeStoredCredential(ctx, user.ID, rec.CredentialID, rec.PublicKey, rec.SignCount)
		if ok {
			creds = append(creds, cred)
		}
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

// webAuthnUserFromSignup returns the WebAuthn user for a signup whose passkey is registered, or nil if the signup can't be used to sign in
func webAuthnUserFromSignup(ctx context.Context, signup *actors.Signup) *v2WebAuthnUser {
	if signup == nil || signup.Phase != actors.SignupPhaseRegistered || signup.Credential == nil {
		return nil
	}

	cred, ok := decodeStoredCredential(ctx, signup.UserID, signup.Credential.ID, signup.Credential.PublicKey, signup.Credential.SignCount)
	if !ok {
		return nil
	}

	id, err := base64.RawURLEncoding.DecodeString(signup.WebAuthnUserID)
	if err != nil {
		return nil
	}

	displayName := signup.DisplayName
	if displayName == "" {
		displayName = signup.UserID
	}

	return &v2WebAuthnUser{
		id:          id,
		userID:      signup.UserID,
		displayName: displayName,
		credentials: []webauthnlib.Credential{cred},
	}
}

// decodeStoredCredential decodes a WebAuthn credential stored as JSON, with its sign count
// It returns false if the credential can't be used
func decodeStoredCredential(ctx context.Context, userID string, credentialID string, publicKey string, signCount int64) (webauthnlib.Credential, bool) {
	var cred webauthnlib.Credential
	err := json.Unmarshal([]byte(publicKey), &cred)
	if err != nil {
		return cred, false
	}

	// The DB stores sign_count as int64 to accommodate any authenticator, but the webauthn library exposes it as uint32
	// Guard against silent wrap-around: a wrap to 0 (or any smaller value) would look like a replay and either lock out the user or conceal a real clone
	// Reject the credential and log it instead of narrowing
	if signCount < 0 || signCount > math.MaxUint32 {
		logging.LogFromContext(ctx).WarnContext(ctx,
			"Credential sign count out of uint32 range; skipping credential",
			slog.String("user_id", userID),
			slog.String("credential_id", credentialID),
			slog.Int64("sign_count", signCount),
		)
		return cred, false
	}

	cred.Authenticator.SignCount = uint32(signCount)
	return cred, true
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
