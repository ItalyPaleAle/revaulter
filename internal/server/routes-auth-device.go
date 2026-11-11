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

	"github.com/italypaleale/revaulter/internal/actors"
	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
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

	payload, err := json.Marshal(v2DeviceLoginChallengePayload{
		UserID:       req.UserID,
		CredentialID: req.CredentialID,
		Challenge:    challenge,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Store the challenge in its revaulter.challenge actor, which deletes it once it expires
	expiresAt := time.Now().Add(deviceLoginChallengeTTL)
	challengeID, err := s.actors.BeginChallenge(c.Request.Context(), actors.ChallengeKindDeviceLogin, "", expiresAt, payload)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.JSON(http.StatusOK, protocolv2.DeviceLoginBeginResponse{
		ChallengeID: challengeID,
		Challenge:   challenge,
		ExpiresAt:   expiresAt.Unix(),
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
	res, err := s.deviceLoginFinish(c, &req, sigP256, sigMldsa65)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(), "Device login failed",
			slog.String("client_ip", c.ClientIP()),
		)

		// The success row is written only when the login is recorded, so record the failure separately
		s.auditEvent(c, auditFields{
			EventType:  db.AuditAuthDeviceLoginFinish,
			Outcome:    db.AuditOutcomeFailure,
			AuthMethod: db.AuditAuthMethodNone,
		})

		AbortWithErrorJSON(c, err)
		return
	}

	// Throttle wrapped primary key delivery, exactly as for passkey logins
	allowed, retryAfter := s.wrappedKeyLimiter.Allow(c.Request.Context(), res.user.ID)
	if !allowed {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
			"Refused wrapped-key delivery: per-user rate limit exceeded",
			slog.String("user_id", res.user.ID),
			slog.String("client_ip", c.ClientIP()),
		)

		setRetryAfter(c, retryAfter)
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

func (s *Server) deviceLoginFinish(c *gin.Context, req *protocolv2.DeviceLoginFinishRequest, sigP256 []byte, sigMldsa65 []byte) (loginFinishRes, error) {
	as := s.db.AuthStore()
	ctx := c.Request.Context()

	// Consume the challenge and retrieve the payload, so the challenge can be used once only
	// The challenge isn't bound to a session (the signatures are what authenticate), so it isn't bound to a user either
	payloadJSON, err := s.actors.ConsumeChallenge(ctx, actors.ChallengeKindDeviceLogin, req.ChallengeID, "")
	if errors.Is(err, actors.ErrInvalidChallenge) {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	} else if err != nil {
		return loginFinishRes{}, err
	}

	var payload v2DeviceLoginChallengePayload
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return loginFinishRes{}, NewResponseError(http.StatusConflict, "Login challenge is invalid or expired")
	}

	// The challenge was issued for one credential
	if payload.UserID == "" || payload.Challenge == "" || payload.CredentialID != req.CredentialID {
		return loginFinishRes{}, invalidLoginResponseError
	}

	user, err := as.GetUserByID(ctx, payload.UserID)
	if err != nil {
		return loginFinishRes{}, err
	}
	if user == nil || user.Status != "active" || !user.Ready {
		return loginFinishRes{}, invalidLoginResponseError
	}

	cred, err := as.GetCredentialForUser(ctx, user.ID, payload.CredentialID)
	if err != nil {
		return loginFinishRes{}, err
	}
	if cred == nil || cred.CredentialType != protocolv2.CredentialTypeDevice {
		return loginFinishRes{}, invalidLoginResponseError
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

	sess, err := newAuthSessionToken(user, config.Get().SessionTimeout)
	if err != nil {
		return loginFinishRes{}, err
	}

	// Update last_used_at and write the audit log entry atomically
	return db.ExecuteInTransaction(ctx, s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (loginFinishRes, error) {
		// Device keys can't be cloned, so the sign count stays as stored
		rErr := tx.AuthStore().Login(ctx, db.LoginInput{
			UserID:       user.ID,
			CredentialID: cred.CredentialID,
			SignCount:    cred.SignCount,
			SessionTTL:   config.Get().SessionTimeout,
		})
		if errors.Is(rErr, db.ErrInvalidLogin) {
			return loginFinishRes{}, invalidLoginResponseError
		} else if rErr != nil {
			return loginFinishRes{}, rErr
		}

		rErr = s.auditEventTx(c, tx, auditFields{
			EventType:    db.AuditAuthDeviceLoginFinish,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSession,
			ActorUserID:  user.ID,
			TargetUserID: user.ID,
			CredentialID: cred.CredentialID,
		})
		if rErr != nil {
			return loginFinishRes{}, rErr
		}

		return loginFinishRes{
			user: user,
			sess: sess,
			cred: cred,
		}, nil
	})
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

// isDeviceCredentialID reports whether id has the format of a device credential ID: base64url of protocolv2.DeviceCredentialIDSize bytes
func isDeviceCredentialID(id string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == protocolv2.DeviceCredentialIDSize
}
