package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/actors"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
	// maxPairingHelloBodySize caps the body of the unauthenticated hello route
	// A hello is about 10 KB: the ML-DSA-65 and ML-KEM-768 public keys and the ML-DSA-65 signature, all base64url
	maxPairingHelloBodySize = 16 << 10
	// maxPairingUserIDLength bounds the user ID accepted by the unauthenticated pairing routes
	maxPairingUserIDLength = 128
)

// Pairing routes
// The existing client creates a session, shows the payload, then reads the device's hello, sends a nonce and completes the pairing; it authenticates with its session
// The new device sends its hello and polls the session's status; it has no session, and the user ID and 128-bit session ID from the payload are its capability for the session's 5-minute lifetime
// Nothing the unauthenticated routes return needs to stay secret: the nonce is authenticated by a MAC that only the two clients can compute
// Each user has at most one session, held by the user's revaulter.pairing actor

// RouteV2PairingCreate is the handler for POST /v2/auth/pairing/create
func (s *Server) RouteV2PairingCreate(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	var req protocolv2.PairingCreateRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	err = protocolv2.ValidatePairingServer(req.Server)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid server: %v", err))
		return
	}

	p, err := s.pairingCreate(c, userID, req.Server)
	if err != nil {
		s.auditPairingFailure(c, db.AuditAuthPairingCreate, userID, db.AuditAuthMethodSession)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Pairing session created",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, protocolv2.PairingCreateResponse{
		SessionID: p.SessionID,
		ExpiresAt: p.ExpiresAt.Unix(),
	})
}

func (s *Server) pairingCreate(c *gin.Context, userID string, server string) (*actors.PairingSession, error) {
	ctx := c.Request.Context()

	// The session JWT's Ready claim is a snapshot from token mint time, so re-check the stored user
	user, err := s.db.AuthStore().GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return nil, NewResponseError(http.StatusForbidden, "User account is not active")
	}

	// The device pins the anchor fingerprint from the payload, and the completion is signed by the anchor
	if computeAnchorFingerprint(user) == "" {
		return nil, NewResponseError(http.StatusConflict, "Account has no anchor key")
	}

	pending, err := s.actors.HasPendingAddCredentialChallenge(ctx, userID)
	if err != nil {
		return nil, NewResponseError(http.StatusInternalServerError, "Failed to check pending challenges")
	}
	if pending {
		return nil, NewResponseError(http.StatusConflict, "Cannot pair a device while a passkey registration is in progress")
	}

	sessionID, err := actors.NewPairingSessionID()
	if err != nil {
		return nil, err
	}

	// This replaces any session the user still had open
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthPairingCreate,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		TargetUserID: userID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": sessionID,
		}),
	})
	return s.actors.Pairing(userID).Create(ctx, sessionID, server, protocolv2.PairingTTL, &audit)
}

// RouteV2PairingHello is the handler for POST /v2/auth/pairing/hello
// It is called by the new device, without a session
func (s *Server) RouteV2PairingHello(c *gin.Context) {
	var req protocolv2.PairingHelloRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if !isPairingUserID(req.UserID) || !isPairingSessionID(req.SessionID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid userId or sessionId"))
		return
	}

	// Check sizes and key encodings before loading the session
	keys, err := req.Hello.Validate()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid hello: %v", err))
		return
	}

	pairing := s.actors.Pairing(req.UserID)
	p, err := pairing.Get(c.Request.Context(), req.SessionID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if p == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Pairing session not found"))
		return
	}

	// The session's owner is known now, so failures are recorded against them
	err = s.pairingHello(c, pairing, p, &req.Hello, keys)
	if err != nil {
		s.auditPairingFailure(c, db.AuditAuthPairingHello, p.UserID, db.AuditAuthMethodNone)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Pairing hello received",
		slog.String("user_id", p.UserID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

func (s *Server) pairingHello(c *gin.Context, pairing actors.PairingClient, p *actors.PairingSession, hello *protocolv2.PairingHello, keys *protocolv2.ParsedDevicePublicKeys) error {
	ctx := c.Request.Context()
	as := s.db.AuthStore()

	if !p.IsOpen(time.Now()) || p.Status != protocolv2.PairingStatusCreated {
		return NewResponseError(http.StatusConflict, "Pairing session is not waiting for a device")
	}

	user, err := as.GetUserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return NewResponseError(http.StatusConflict, "Pairing session is not waiting for a device")
	}

	// Rebuild the transcript from the server's own state, so the device's signatures prove it answered this session's payload
	anchorFingerprint := computeAnchorFingerprint(user)
	if anchorFingerprint == "" {
		return NewResponseError(http.StatusConflict, "Account has no anchor key")
	}
	transcript := protocolv2.NewPairingTranscript(p.Server, p.UserID, p.SessionID, anchorFingerprint, hello)

	// Validate already checked the signature sizes
	sigP256, _ := base64.RawURLEncoding.DecodeString(hello.SignatureP256)
	sigMldsa65, _ := base64.RawURLEncoding.DecodeString(hello.SignatureMldsa65)
	err = protocolv2.VerifyPairingHelloSignatures(keys, &transcript, sigP256, sigMldsa65)
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "hello signature verification failed: %v", err)
	}

	// Catch a credential ID collision now rather than at completion
	existing, err := as.GetCredentialForUser(ctx, p.UserID, hello.CredentialID)
	if err != nil {
		return err
	}
	if existing != nil {
		return NewResponseError(http.StatusConflict, "Credential is already registered")
	}

	// The actor checks again that the session is waiting for a hello, in the same turn that stores it
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthPairingHello,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodNone,
		ActorUserID:  p.UserID,
		TargetUserID: p.UserID,
		CredentialID: hello.CredentialID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": p.SessionID,
		}),
	})
	_, err = pairing.Hello(ctx, p.SessionID, *hello, &audit)
	return pairingResponseError(err, "Pairing session is not waiting for a device")
}

// RouteV2PairingGet is the handler for GET /v2/auth/pairing/:id
// The existing client polls it until the device's hello arrives
func (s *Server) RouteV2PairingGet(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	p, err := s.getOwnPairingSession(c, userID, c.Param("id"))
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, protocolv2.PairingSessionResponse{
		SessionID: p.SessionID,
		Status:    p.ReportedStatus(time.Now()),
		ExpiresAt: p.ExpiresAt.Unix(),
		Hello:     p.Hello,
	})
}

// RouteV2PairingNonce is the handler for POST /v2/auth/pairing/nonce
// The server can't check the nonce's MAC: only the new device, which has the payload secret, can
func (s *Server) RouteV2PairingNonce(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	var req protocolv2.PairingNonceRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if !isPairingSessionID(req.SessionID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid sessionId"))
		return
	}
	if !isBase64URLOfSize(req.Nonce, protocolv2.PairingNonceSize) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid nonce"))
		return
	}
	if !isBase64URLOfSize(req.NonceMAC, protocolv2.PairingMACSize) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid nonceMac"))
		return
	}

	_, err = s.actors.Pairing(userID).Nonce(c.Request.Context(), req.SessionID, req.Nonce, req.NonceMAC)
	err = pairingResponseError(err, "Pairing session is not waiting for a nonce")
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

// RouteV2PairingDeviceStatus is the handler for POST /v2/auth/pairing/device-status
// The new device polls it, without a session, until the nonce arrives and then until the pairing completes
func (s *Server) RouteV2PairingDeviceStatus(c *gin.Context) {
	var req protocolv2.PairingDeviceStatusRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if !isPairingUserID(req.UserID) || !isPairingSessionID(req.SessionID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid userId or sessionId"))
		return
	}

	p, err := s.actors.Pairing(req.UserID).Get(c.Request.Context(), req.SessionID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if p == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Pairing session not found"))
		return
	}

	c.JSON(http.StatusOK, protocolv2.PairingDeviceStatusResponse{
		Status:    p.ReportedStatus(time.Now()),
		ExpiresAt: p.ExpiresAt.Unix(),
		Nonce:     p.Nonce,
		NonceMAC:  p.NonceMAC,
	})
}

// RouteV2PairingComplete is the handler for POST /v2/auth/pairing/complete
func (s *Server) RouteV2PairingComplete(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	var req protocolv2.PairingCompleteRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}

	vals, err := parsePairingCompleteRequest(&req)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	vals.userID = userID

	res, err := s.pairingComplete(c, vals)
	if err != nil {
		s.auditPairingFailure(c, db.AuditAuthPairingComplete, userID, db.AuditAuthMethodSession)
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Device paired",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, res)
}

type pairingCompleteVals struct {
	userID        string
	req           *protocolv2.PairingCompleteRequest
	displayName   string
	attestPayload protocolv2.AttestationPayloadV2
	attestSigEs   []byte
	attestSigMl   []byte
}

// parsePairingCompleteRequest checks everything in the request that doesn't need the database or the session
func parsePairingCompleteRequest(req *protocolv2.PairingCompleteRequest) (pairingCompleteVals, error) {
	if !isPairingSessionID(req.SessionID) {
		return pairingCompleteVals{}, NewResponseError(http.StatusBadRequest, "Invalid sessionId")
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if len(displayName) > protocolv2.MaxDeviceNameLength {
		return pairingCompleteVals{}, NewResponseError(http.StatusBadRequest, "displayName is too long")
	}

	// The device unwraps the primary key with its Secure Enclave keys, so the wrapper must be a device envelope
	env, err := protocolv2.ParseWrappedPrimaryKeyEnvelope(req.WrappedPrimaryKey)
	if err != nil {
		return pairingCompleteVals{}, NewResponseErrorf(http.StatusBadRequest, "invalid wrappedPrimaryKey: %v", err)
	}
	if !env.IsDevice() {
		return pairingCompleteVals{}, NewResponseError(http.StatusBadRequest, "invalid wrappedPrimaryKey: not a device envelope")
	}

	err = validateWrappedAnchorEnvelope(req.WrappedAnchorKey)
	if err != nil {
		return pairingCompleteVals{}, NewResponseErrorf(http.StatusBadRequest, "invalid wrappedAnchorKey: %v", err)
	}

	attestPayload, err := protocolv2.ParseAttestationPayloadV2(req.AttestationPayload)
	if err != nil {
		return pairingCompleteVals{}, NewResponseErrorf(http.StatusBadRequest, "invalid attestationPayload: %v", err)
	}
	attestSigEs, attestSigMl, err := parseHybridSignatures(req.AttestationSignatureEs384, req.AttestationSignatureMldsa87)
	if err != nil {
		return pairingCompleteVals{}, NewResponseErrorf(http.StatusBadRequest, "invalid attestationSignature: %v", err)
	}

	return pairingCompleteVals{
		req:           req,
		displayName:   displayName,
		attestPayload: attestPayload,
		attestSigEs:   attestSigEs,
		attestSigMl:   attestSigMl,
	}, nil
}

func (s *Server) pairingComplete(c *gin.Context, vals pairingCompleteVals) (protocolv2.PairingCompleteResponse, error) {
	ctx := c.Request.Context()
	now := time.Now()

	p, err := s.getOwnPairingSession(c, vals.userID, vals.req.SessionID)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, err
	}
	if !p.IsOpen(now) || p.Status != protocolv2.PairingStatusNonce || p.Hello == nil {
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "Pairing session is not ready to complete")
	}
	hello := p.Hello

	// The session JWT's Ready claim is a snapshot from token mint time, so re-check the stored user
	user, err := s.db.AuthStore().GetUserByID(ctx, vals.userID)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusForbidden, "User account is not active")
	}

	// The anchor signature is what binds the device to the user's identity root
	anchorEs384Pub, mldsa87PubBytes, err := parseAnchorPubkeys(user.AnchorEs384PublicKey, user.AnchorMldsa87PublicKey)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, NewResponseErrorf(http.StatusInternalServerError, "stored anchor public key is invalid: %v", err)
	}
	err = protocolv2.VerifyHybridAttestationV2(anchorEs384Pub, mldsa87PubBytes, &vals.attestPayload, vals.attestSigEs, vals.attestSigMl)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, NewResponseErrorf(http.StatusBadRequest, "attestation signature verification failed: %v", err)
	}

	// Compare every signed field against server-side values
	err = vals.attestPayload.ValidateCreatedAt(now, attestationCreatedAtSkew)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, NewResponseErrorf(http.StatusBadRequest, "attestationPayload %v", err)
	}
	switch {
	case vals.attestPayload.UserID != vals.userID:
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusBadRequest, "attestationPayload userId does not match session")
	case vals.attestPayload.CredentialType != protocolv2.CredentialTypeDevice:
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialType must be device")
	case vals.attestPayload.CredentialID != hello.CredentialID:
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialId does not match the device")
	case vals.attestPayload.CredentialPublicKeyHash != hello.PublicKeys.Hash():
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusBadRequest, "attestationPayload credentialPublicKeyHash does not match the device")
	case vals.attestPayload.WrappedKeyEpoch != user.WrappedKeyEpoch:
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusBadRequest, "attestationPayload wrappedKeyEpoch does not match current user epoch")
	}

	displayName := vals.displayName
	if displayName == "" {
		displayName = hello.DeviceName
	}
	publicKeyJSON, err := json.Marshal(hello.PublicKeys)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, err
	}

	// The actor adds the credential and closes the session in one turn
	// The insert also requires the user to still be at the attested epoch, so a password change that lands in between fails the completion
	recordID := uuid.NewV4().String()
	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthPairingComplete,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  vals.userID,
		TargetUserID: vals.userID,
		CredentialID: hello.CredentialID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": p.SessionID,
		}),
	})
	_, err = s.actors.Pairing(vals.userID).Complete(ctx, p.SessionID, db.AddCredentialInput{
		ID:                          recordID,
		UserID:                      vals.userID,
		CredentialID:                hello.CredentialID,
		DisplayName:                 displayName,
		CredentialType:              protocolv2.CredentialTypeDevice,
		PublicKey:                   string(publicKeyJSON),
		WrappedPrimaryKey:           vals.req.WrappedPrimaryKey,
		WrappedAnchorKey:            vals.req.WrappedAnchorKey,
		AttestationPayload:          vals.req.AttestationPayload,
		AttestationSignatureEs384:   vals.req.AttestationSignatureEs384,
		AttestationSignatureMldsa87: vals.req.AttestationSignatureMldsa87,
		WrappedKeyEpoch:             vals.attestPayload.WrappedKeyEpoch,
	}, &audit)
	switch {
	case errors.Is(err, db.ErrCredentialAlreadyExists):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "Credential is already registered")
	case errors.Is(err, db.ErrWrappedKeyEpochChanged):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "The password changed while the device was being paired")
	case errors.Is(err, db.ErrUserNotFound):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusForbidden, "User account is not active")
	}
	err = pairingResponseError(err, "Pairing session is not ready to complete")
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, err
	}

	return protocolv2.PairingCompleteResponse{
		ID:           recordID,
		CredentialID: hello.CredentialID,
	}, nil
}

// RouteV2PairingCancel is the handler for POST /v2/auth/pairing/cancel
func (s *Server) RouteV2PairingCancel(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	var req protocolv2.PairingCancelRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if !isPairingSessionID(req.SessionID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid sessionId"))
		return
	}

	audit := s.auditInputFromContext(c, auditFields{
		EventType:    db.AuditAuthPairingCancel,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		TargetUserID: userID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": req.SessionID,
		}),
	})
	_, err = s.actors.Pairing(userID).Cancel(c.Request.Context(), req.SessionID, &audit)
	err = pairingResponseError(err, "Pairing session has already ended")
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

// getOwnPairingSession loads the signed-in user's pairing session with the given ID
// The session ID of another user is reported as not found, since the user's actor doesn't hold it
func (s *Server) getOwnPairingSession(c *gin.Context, userID string, sessionID string) (*actors.PairingSession, error) {
	if !isPairingSessionID(sessionID) {
		return nil, NewResponseError(http.StatusBadRequest, "Invalid session ID")
	}

	p, err := s.actors.Pairing(userID).Get(c.Request.Context(), sessionID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, NewResponseError(http.StatusNotFound, "Pairing session not found")
	}

	return p, nil
}

// pairingResponseError maps the errors of the pairing actor to responses, using stateMsg when the session isn't at the step the operation needs
func pairingResponseError(err error, stateMsg string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, actors.ErrPairingSessionNotFound):
		return NewResponseError(http.StatusNotFound, "Pairing session not found")
	case errors.Is(err, actors.ErrPairingSessionState):
		return NewResponseError(http.StatusConflict, stateMsg)
	default:
		return err
	}
}

// auditPairingFailure records a failed pairing step
func (s *Server) auditPairingFailure(c *gin.Context, eventType db.EventType, userID string, authMethod db.AuditAuthMethod) {
	s.auditEvent(c, auditFields{
		EventType:    eventType,
		Outcome:      db.AuditOutcomeFailure,
		AuthMethod:   authMethod,
		ActorUserID:  userID,
		TargetUserID: userID,
	})
}

// isPairingUserID reports whether id can be the user ID of a pairing session
func isPairingUserID(id string) bool {
	return id != "" && len(id) <= maxPairingUserIDLength && !strings.ContainsRune(id, '/')
}

// isPairingSessionID reports whether id has the format of a pairing session ID
func isPairingSessionID(id string) bool {
	return isBase64URLOfSize(id, protocolv2.PairingSessionIDSize)
}

// isBase64URLOfSize reports whether value is the strict base64url (raw, no padding) encoding of exactly size bytes
func isBase64URLOfSize(value string, size int) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(b) == size
}
