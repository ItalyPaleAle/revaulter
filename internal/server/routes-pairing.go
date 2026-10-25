package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// maxPairingHelloBodySize caps the body of the unauthenticated hello route
// A hello is about 10 KB: the ML-DSA-65 and ML-KEM-768 public keys and the ML-DSA-65 signature, all base64url
const maxPairingHelloBodySize = 16 << 10

// Pairing routes
// The existing client creates a session, shows the payload, then reads the device's hello, sends a nonce and completes the pairing; it authenticates with its session
// The new device sends its hello and polls the session's status; it has no session, and the 128-bit session ID is its capability for the session's 5-minute lifetime
// Nothing the unauthenticated routes return needs to stay secret: the nonce is authenticated by a MAC that only the two clients can compute

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

	p, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.PairingSession, error) {
		return s.pairingCreate(c, tx, userID, req.Server)
	})
	if err != nil {
		s.auditPairingFailure(c, db.AuditAuthPairingCreate, userID, db.AuditAuthMethodSession)
		AbortWithErrorJSON(c, err)
		return
	}

	// Enqueue the session for cleanup when it expires
	err = s.deleteQueue.Enqueue(deleteEvent{
		KeyName: "pairing-delete:" + p.ID,
		Kind:    "pairing",
		ID:      p.ID,
		TTL:     p.ExpiresAt.Add(10 * time.Minute),
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Pairing session created",
		slog.String("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, protocolv2.PairingCreateResponse{
		SessionID: p.ID,
		ExpiresAt: p.ExpiresAt.Unix(),
	})
}

func (s *Server) pairingCreate(c *gin.Context, tx *db.DbTx, userID string, server string) (*db.PairingSession, error) {
	ctx := c.Request.Context()
	as := tx.AuthStore()

	// The session JWT's Ready claim is a snapshot from token mint time, so re-check the stored user
	user, err := as.GetUserByID(ctx, userID)
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

	pending, err := as.HasPendingChallenge(ctx, userID, "add-credential")
	if err != nil {
		return nil, NewResponseError(http.StatusInternalServerError, "Failed to check pending challenges")
	}
	if pending {
		return nil, NewResponseError(http.StatusConflict, "Cannot pair a device while a passkey registration is in progress")
	}

	// This cancels any session the user still had open
	p, err := as.CreatePairingSession(ctx, userID, server, protocolv2.PairingTTL)
	if errors.Is(err, db.ErrUserNotFound) {
		return nil, NewResponseError(http.StatusForbidden, "User account is not active")
	} else if err != nil {
		return nil, err
	}

	err = s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthPairingCreate,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		TargetUserID: userID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": p.ID,
		}),
	})
	if err != nil {
		return nil, err
	}

	return p, nil
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
	if !isPairingSessionID(req.SessionID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid sessionId"))
		return
	}

	// Check sizes and key encodings before touching the database
	keys, err := req.Hello.Validate()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid hello: %v", err))
		return
	}

	// The session's owner is known once the session is loaded, so failures past that point are recorded against them
	var ownerID string
	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		p, rErr := tx.AuthStore().GetPairingSession(ctx, req.SessionID)
		if errors.Is(rErr, db.ErrPairingSessionNotFound) {
			return struct{}{}, NewResponseError(http.StatusNotFound, "Pairing session not found")
		} else if rErr != nil {
			return struct{}{}, rErr
		}

		ownerID = p.UserID
		return struct{}{}, s.pairingHello(c, tx, p, &req.Hello, keys)
	})
	if err != nil {
		if ownerID != "" {
			s.auditPairingFailure(c, db.AuditAuthPairingHello, ownerID, db.AuditAuthMethodNone)
		}
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Pairing hello received",
		slog.String("user_id", ownerID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

func (s *Server) pairingHello(c *gin.Context, tx *db.DbTx, p *db.PairingSession, hello *protocolv2.PairingHello, keys *protocolv2.ParsedDevicePublicKeys) error {
	ctx := c.Request.Context()
	as := tx.AuthStore()
	now := time.Now()

	if !p.IsOpen(now) || p.Status != protocolv2.PairingStatusCreated {
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
	transcript := protocolv2.NewPairingTranscript(p.Server, p.UserID, p.ID, anchorFingerprint, hello)

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

	helloJSON, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	err = as.SetPairingHello(ctx, p.ID, string(helloJSON), now)
	if errors.Is(err, db.ErrPairingSessionState) {
		return NewResponseError(http.StatusConflict, "Pairing session is not waiting for a device")
	} else if err != nil {
		return err
	}

	return s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthPairingHello,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodNone,
		ActorUserID:  p.UserID,
		TargetUserID: p.UserID,
		CredentialID: hello.CredentialID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": p.ID,
		}),
	})
}

// RouteV2PairingGet is the handler for GET /v2/auth/pairing/:id
// The existing client polls it until the device's hello arrives
func (s *Server) RouteV2PairingGet(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	p, err := s.getOwnPairingSession(c.Request.Context(), s.db.AuthStore(), c.Param("id"), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	res := protocolv2.PairingSessionResponse{
		SessionID: p.ID,
		Status:    pairingStatus(p, time.Now()),
		ExpiresAt: p.ExpiresAt.Unix(),
	}
	if p.Hello != "" {
		var hello protocolv2.PairingHello
		err = json.Unmarshal([]byte(p.Hello), &hello)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusInternalServerError, "stored pairing hello is invalid: %v", err))
			return
		}
		res.Hello = &hello
	}

	c.JSON(http.StatusOK, res)
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
	if !isBase64URLOfSize(req.Nonce, protocolv2.PairingNonceSize) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid nonce"))
		return
	}
	if !isBase64URLOfSize(req.NonceMAC, protocolv2.PairingMACSize) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid nonceMac"))
		return
	}

	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		as := tx.AuthStore()

		_, err := s.getOwnPairingSession(ctx, as, req.SessionID, userID)
		if err != nil {
			return struct{}{}, err
		}

		err = as.SetPairingNonce(ctx, req.SessionID, userID, req.Nonce, req.NonceMAC, time.Now())
		if errors.Is(err, db.ErrPairingSessionState) {
			return struct{}{}, NewResponseError(http.StatusConflict, "Pairing session is not waiting for a nonce")
		}
		return struct{}{}, err
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

// RouteV2PairingDeviceStatus is the handler for GET /v2/auth/pairing/:id/device
// The new device polls it, without a session, until the nonce arrives and then until the pairing completes
func (s *Server) RouteV2PairingDeviceStatus(c *gin.Context) {
	id := c.Param("id")
	if !isPairingSessionID(id) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid session ID"))
		return
	}

	p, err := s.db.AuthStore().GetPairingSession(c.Request.Context(), id)
	if errors.Is(err, db.ErrPairingSessionNotFound) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Pairing session not found"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, protocolv2.PairingDeviceStatusResponse{
		Status:    pairingStatus(p, time.Now()),
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

	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (protocolv2.PairingCompleteResponse, error) {
		return s.pairingComplete(c, tx, vals)
	})
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

// parsePairingCompleteRequest checks everything in the request that doesn't need the database
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

func (s *Server) pairingComplete(c *gin.Context, tx *db.DbTx, vals pairingCompleteVals) (protocolv2.PairingCompleteResponse, error) {
	ctx := c.Request.Context()
	as := tx.AuthStore()
	now := time.Now()

	p, err := s.getOwnPairingSession(ctx, as, vals.req.SessionID, vals.userID)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, err
	}
	if !p.IsOpen(now) || p.Status != protocolv2.PairingStatusNonce {
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "Pairing session is not ready to complete")
	}

	var hello protocolv2.PairingHello
	err = json.Unmarshal([]byte(p.Hello), &hello)
	if err != nil {
		return protocolv2.PairingCompleteResponse{}, NewResponseErrorf(http.StatusInternalServerError, "stored pairing hello is invalid: %v", err)
	}

	// The session JWT's Ready claim is a snapshot from token mint time, so re-check the stored user
	user, err := as.GetUserByID(ctx, vals.userID)
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

	recordID := uuid.NewV4().String()
	err = as.CompletePairing(ctx, p.ID, db.AddCredentialInput{
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
	}, now)
	switch {
	case errors.Is(err, db.ErrPairingSessionState):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "Pairing session is not ready to complete")
	case errors.Is(err, db.ErrCredentialAlreadyExists):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusConflict, "Credential is already registered")
	case errors.Is(err, db.ErrUserNotFound):
		return protocolv2.PairingCompleteResponse{}, NewResponseError(http.StatusForbidden, "User account is not active")
	case err != nil:
		return protocolv2.PairingCompleteResponse{}, err
	}

	err = s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthPairingComplete,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  vals.userID,
		TargetUserID: vals.userID,
		CredentialID: hello.CredentialID,
		Metadata: jsonMetadata(map[string]any{
			"pairingSessionId": p.ID,
		}),
	})
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

	_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		as := tx.AuthStore()

		_, err := s.getOwnPairingSession(ctx, as, req.SessionID, userID)
		if err != nil {
			return struct{}{}, err
		}

		err = as.CancelPairingSession(ctx, req.SessionID, userID, time.Now())
		if errors.Is(err, db.ErrPairingSessionState) {
			return struct{}{}, NewResponseError(http.StatusConflict, "Pairing session has already ended")
		} else if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthPairingCancel,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  userID,
			TargetUserID: userID,
			Metadata: jsonMetadata(map[string]any{
				"pairingSessionId": req.SessionID,
			}),
		})
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, v2AuthOKResponse{
		OK: true,
	})
}

// getOwnPairingSession loads a pairing session that belongs to userID
// A session of another user is reported as not found, so its existence isn't revealed
func (s *Server) getOwnPairingSession(ctx context.Context, as *db.AuthStore, id string, userID string) (*db.PairingSession, error) {
	if !isPairingSessionID(id) {
		return nil, NewResponseError(http.StatusBadRequest, "Invalid session ID")
	}

	p, err := as.GetPairingSession(ctx, id)
	if errors.Is(err, db.ErrPairingSessionNotFound) {
		return nil, NewResponseError(http.StatusNotFound, "Pairing session not found")
	} else if err != nil {
		return nil, err
	}
	if p.UserID != userID {
		return nil, NewResponseError(http.StatusNotFound, "Pairing session not found")
	}

	return p, nil
}

// auditPairingFailure records a failed pairing step outside the rolled-back transaction
func (s *Server) auditPairingFailure(c *gin.Context, eventType db.EventType, userID string, authMethod db.AuditAuthMethod) {
	s.auditEvent(c, auditFields{
		EventType:    eventType,
		Outcome:      db.AuditOutcomeFailure,
		AuthMethod:   authMethod,
		ActorUserID:  userID,
		TargetUserID: userID,
	})
}

// pairingStatus returns the status reported to clients, which is expired for a session that is still open past its expiry
func pairingStatus(p *db.PairingSession, now time.Time) string {
	switch p.Status {
	case protocolv2.PairingStatusCompleted, protocolv2.PairingStatusCanceled:
		return p.Status
	}

	if !p.IsOpen(now) {
		return protocolv2.PairingStatusExpired
	}

	return p.Status
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
