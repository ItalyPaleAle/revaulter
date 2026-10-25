package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/go-kit/eventqueue"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
	// deviceLoginChallengeKind is the auth challenge kind for device logins
	deviceLoginChallengeKind = "device-login"
	// deviceLoginChallengeTTL is how long a device has to sign the login challenge
	deviceLoginChallengeTTL = 60 * time.Second
	// deviceLoginChallengeSize is the number of random bytes in a device login challenge
	deviceLoginChallengeSize = 32
	// maxDeviceLoginUserIDLength bounds the user ID accepted by the unauthenticated begin route
	maxDeviceLoginUserIDLength = 128
)

type v2DeviceLoginChallengePayload struct {
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
	Challenge    string `json:"challenge"`
}

// RouteV2AuthDeviceLoginBegin is the handler for POST /v2/auth/device/login/begin
// It answers the same way whether or not the user and credential exist, so it doesn't reveal which do
func (s *Server) RouteV2AuthDeviceLoginBegin(c *gin.Context) {
	var req protocolv2.DeviceLoginBeginRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.UserID == "" || len(req.UserID) > maxDeviceLoginUserIDLength {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid userId"))
		return
	}
	if !isDeviceCredentialID(req.CredentialID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid credentialId"))
		return
	}

	challengeBytes := make([]byte, deviceLoginChallengeSize)
	_, err = rand.Read(challengeBytes)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	// BeginChallenge must be executed in a transaction
	ch, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 20*time.Second, func(ctx context.Context, tx *db.DbTx) (*db.AuthChallenge, error) {
		return tx.AuthStore().BeginChallenge(ctx, deviceLoginChallengeKind, req.UserID, challenge, time.Now().UTC().Add(deviceLoginChallengeTTL), v2DeviceLoginChallengePayload{
			UserID:       req.UserID,
			CredentialID: req.CredentialID,
			Challenge:    challenge,
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

	c.JSON(http.StatusOK, protocolv2.DeviceLoginBeginResponse{
		ChallengeID: ch.ID,
		Challenge:   challenge,
		ExpiresAt:   ch.ExpiresAt.Unix(),
	})
}

// RouteV2AuthDeviceLoginFinish is the handler for POST /v2/auth/device/login/finish
// The session token is returned in the body for the app to send as a bearer token; no cookie is set
func (s *Server) RouteV2AuthDeviceLoginFinish(c *gin.Context) {
	var req protocolv2.DeviceLoginFinishRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.ChallengeID == "" || req.CredentialID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing required login fields"))
		return
	}

	sigP256, err := protocolv2.DecodeBase64Signature(req.SignatureP256, protocolv2.P256SignatureSize)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid signatureP256: %v", err))
		return
	}
	sigMldsa65, err := protocolv2.DecodeBase64Signature(req.SignatureMldsa65, protocolv2.MLDSA65SignatureSize)
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "invalid signatureMldsa65: %v", err))
		return
	}

	// Finish the login
	// This must be executed in a transaction
	res, err := db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (loginFinishRes, error) {
		return s.deviceLoginFinish(c, tx, &req, sigP256, sigMldsa65)
	})
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Device login failed",
			slog.String("client_ip", c.ClientIP()),
		)

		// The transaction rolled back, so any in-tx success row never landed; record the failure outside the tx
		s.auditEvent(c, auditFields{
			EventType:  db.AuditAuthDeviceLoginFinish,
			Outcome:    db.AuditOutcomeFailure,
			AuthMethod: db.AuditAuthMethodNone,
		})

		AbortWithErrorJSON(c, err)
		return
	}

	// Remove the challenge from the cleanup queue
	err = s.deleteQueue.Dequeue("challenge-delete:" + req.ChallengeID)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	// Throttle wrapped primary key delivery, exactly as for passkey logins
	overLimit := s.wrappedKeyLimiter.OnLimit(c.Writer, c.Request, "v2-wrapped-key:"+res.user.ID)
	if overLimit {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
			"Refused wrapped-key delivery: per-user rate limit exceeded",
			slog.String("user_id", res.user.ID),
			slog.String("client_ip", c.ClientIP()),
		)

		AbortWithErrorJSON(c, NewResponseError(http.StatusTooManyRequests, "Too many login attempts; please retry later"))
		return
	}

	token, err := signAuthSessionToken(res.sess)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	logging.LogFromContext(c.Request.Context()).InfoContext(c.Request.Context(), "Device logged in and delivered wrapped primary key",
		slog.String("user_id", res.user.ID),
		slog.String("client_ip", c.ClientIP()),
	)

	c.JSON(http.StatusOK, protocolv2.DeviceLoginFinishResponse{
		Authenticated:             true,
		SessionToken:              token,
		SessionExpiresAt:          res.sess.ExpiresAt.Unix(),
		UserID:                    res.user.ID,
		WrappedPrimaryKey:         res.cred.WrappedPrimaryKey,
		WrappedAnchorKey:          res.cred.WrappedAnchorKey,
		CredentialWrappedKeyEpoch: res.cred.WrappedKeyEpoch,
		WrappedKeyStale:           res.cred.WrappedKeyEpoch > 0 && res.cred.WrappedKeyEpoch < res.user.WrappedKeyEpoch,
	})
}

func (s *Server) deviceLoginFinish(c *gin.Context, tx *db.DbTx, req *protocolv2.DeviceLoginFinishRequest, sigP256 []byte, sigMldsa65 []byte) (loginFinishRes, error) {
	as := tx.AuthStore()
	ctx := c.Request.Context()

	// The challenge isn't bound to a session (the signatures are what authenticate), so the consume isn't bound to a userID
	var payload v2DeviceLoginChallengePayload
	err := as.ConsumeChallenge(ctx, req.ChallengeID, deviceLoginChallengeKind, "", &payload)
	if errors.Is(err, db.ErrInvalidChallenge) {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	// The challenge was issued for one credential
	if payload.UserID == "" || payload.Challenge == "" || payload.CredentialID != req.CredentialID {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	user, err := as.GetUserByID(ctx, payload.UserID)
	if err != nil {
		return loginFinishRes{}, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	cred, err := as.GetCredentialForUser(ctx, user.ID, payload.CredentialID)
	if err != nil {
		return loginFinishRes{}, err
	}
	if cred == nil || cred.CredentialType != protocolv2.CredentialTypeDevice {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	}

	keys, err := parseStoredDevicePublicKeys(cred.PublicKey)
	if err != nil {
		return loginFinishRes{}, NewResponseErrorf(http.StatusInternalServerError, "stored device public keys are invalid: %v", err)
	}

	// Build the signed message from server-side state only
	err = protocolv2.VerifyDeviceLogin(keys, &protocolv2.DeviceLoginPayload{
		Challenge:    payload.Challenge,
		CredentialID: cred.CredentialID,
		UserID:       user.ID,
		V:            protocolv2.DeviceLoginVersion,
	}, sigP256, sigMldsa65)
	if err != nil {
		return loginFinishRes{}, NewResponseErrorf(http.StatusUnauthorized, "Device login verification failed: %v", err)
	}

	// Device keys can't be cloned, so the sign count stays as stored; this updates last_used_at
	err = as.Login(ctx, db.LoginInput{
		UserID:       user.ID,
		CredentialID: cred.CredentialID,
		SignCount:    cred.SignCount,
		SessionTTL:   config.Get().SessionTimeout,
	})
	if errors.Is(err, db.ErrInvalidLogin) {
		return loginFinishRes{}, NewResponseError(http.StatusUnauthorized, "Invalid login")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	sess, err := newAuthSessionToken(user, config.Get().SessionTimeout)
	if err != nil {
		return loginFinishRes{}, err
	}

	err = s.auditEventTx(c, tx, auditFields{
		EventType:    db.AuditAuthDeviceLoginFinish,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  user.ID,
		TargetUserID: user.ID,
		CredentialID: cred.CredentialID,
	})
	if err != nil {
		return loginFinishRes{}, err
	}

	return loginFinishRes{
		user: user,
		sess: sess,
		cred: cred,
	}, nil
}

// parseStoredDevicePublicKeys decodes the public_key column of a device credential
func parseStoredDevicePublicKeys(stored string) (*protocolv2.ParsedDevicePublicKeys, error) {
	var pub protocolv2.DevicePublicKeys
	err := json.Unmarshal([]byte(stored), &pub)
	if err != nil {
		return nil, err
	}

	return pub.Parse()
}

// isDeviceCredentialID reports whether id has the format of a device credential ID
func isDeviceCredentialID(id string) bool {
	return isBase64URLOfSize(id, protocolv2.DeviceCredentialIDSize)
}
