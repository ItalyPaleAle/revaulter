package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// v2RequestSigningPubkeyResponse is the response for GET /v2/request/signing-pubkeys
type v2RequestSigningPubkeyResponse struct {
	ID                          string          `json:"id"`
	Algorithm                   string          `json:"algorithm"`
	KeyLabel                    string          `json:"keyLabel"`
	JWK                         json.RawMessage `json:"jwk"`
	PublicationPayload          string          `json:"publicationPayload,omitempty"`
	PublicationSignatureEs384   string          `json:"publicationSignatureEs384,omitempty"`
	PublicationSignatureMldsa87 string          `json:"publicationSignatureMldsa87,omitempty"`
}

type v2RequestPubkeyResponse struct {
	UserID   string          `json:"userId"`
	EcdhP256 json.RawMessage `json:"ecdhP256"`
	Mlkem768 string          `json:"mlkem768"`

	// Hybrid anchor pubkeys + bundle self-signatures
	// The CLI pins the anchor pubkeys (TOFU) and verifies both signatures over the bundle to detect server-side pubkey substitution attacks
	AnchorEs384PublicKey   string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey string `json:"anchorMldsa87PublicKey"`
	// wrappedKeyEpoch is retained for CLIs that predate versioning and only ever reflects the epoch bound into v1 signatures (always 1), NOT the user's live epoch
	WrappedKeyEpoch              int64  `json:"wrappedKeyEpoch"`
	PubkeyBundleVersion          int64  `json:"pubkeyBundleVersion"`
	PubkeyBundleSignatureEs384   string `json:"pubkeyBundleSignatureEs384"`
	PubkeyBundleSignatureMldsa87 string `json:"pubkeyBundleSignatureMldsa87"`
}

// RouteV2RequestCreate is the handler for POST /v2/request/(encrypt|decrypt|sign)
func (s *Server) RouteV2RequestCreate(operation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := config.Get()
		log := logging.LogFromContext(c.Request.Context())
		span := trace.SpanFromContext(c.Request.Context())

		// Get the user from the context
		user := getRequestUserFromCtx(c)
		if user == nil {
			// Should never happen
			AbortWithErrorJSON(c, errors.New("missing request user in context"))
			return
		}

		// Parse the request body, then validate it
		var body protocolv2.RequestCreateBody
		err := c.ShouldBindJSON(&body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request body: %v", err))
			return
		}

		err = validateV2CreateBody(operation, &body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request: %v", err))
			return
		}

		// Get the timeout or set the default one
		timeout := body.GetTimeout()
		if timeout == 0 {
			timeout = cfg.RequestTimeout
		} else if timeout > 24*time.Hour {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request: timeout must not be more than 24 hours"))
			return
		}

		// Generate the token the client uses to retrieve the result
		resultToken, resultTokenHash, err := newResultToken(user.ID)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		now := time.Now()
		state := uuid.NewV4().String()

		encEnvelope := protocolv2.RequestEncEnvelope{
			CliEphemeralPublicKey: body.CliEphemeralPublicKey,
			MlkemCiphertext:       body.MlkemCiphertext,
			Nonce:                 body.EncryptedPayloadNonce,
			Ciphertext:            body.EncryptedPayload,
		}
		encEnvelopeJSON, err := json.Marshal(encEnvelope)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		// Store the request in the user's actor, which also writes the envelope and the audit log event, and notifies the list streams
		auditIn := s.auditInputFromContext(c, auditFields{
			EventType:    db.AuditRequestCreate,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   getRequestAuthMethodFromCtx(c),
			ActorUserID:  user.ID,
			RequestState: state,
			Metadata:     requestCreateAuditMetadata(operation, body.Algorithm, body.KeyLabel, body.Note, getRequestJWTClaimsFromCtx(c)),
		})
		res, err := invokeUserActor[userCreateRes](c.Request.Context(), s, user.ID, userMethodCreate, userCreateReq{
			State: state,
			Request: userRequest{
				Operation:       operation,
				KeyLabel:        body.KeyLabel,
				Algorithm:       body.Algorithm,
				RequestorIP:     c.ClientIP(),
				Note:            body.Note,
				CreatedAt:       now,
				ExpiresAt:       now.Add(timeout),
				ResultTokenHash: resultTokenHash,
			},
			EncryptedRequest: string(encEnvelopeJSON),
			Audit:            &auditIn,
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if res.Error == userActorErrTooManyPending {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusTooManyRequests, "Too many pending requests: a user can have at most %d", maxPendingRequestsPerUser))
			return
		}

		// Send response
		c.JSON(http.StatusAccepted, protocolv2.RequestCreateResponse{
			State:       state,
			Pending:     true,
			ResultToken: resultToken,
		})

		// Notify users via webhook in background when configured
		if s.webhook == nil {
			// Webhooks not configured, skip
			return
		}

		go func() {
			displayName := user.DisplayName
			if displayName == "" {
				displayName = user.ID
			}

			// Use a background context because the request's context is canceled when the handler returns
			webhookCtx := trace.ContextWithSpan(context.Background(), span)
			webhookErr := s.webhook.SendWebhook(webhookCtx, &webhookRequest{
				BaseURL:       s.getBaseURL(),
				OperationName: operation,
				AssignedUser:  displayName,
				KeyLabel:      body.KeyLabel,
				Algorithm:     body.Algorithm,
				Requestor:     c.ClientIP(),
				Note:          body.Note,
			})
			if webhookErr != nil {
				log.ErrorContext(webhookCtx, "Error sending webhook", slog.Any("error", webhookErr))
				return
			}
			log.InfoContext(webhookCtx, "Sent webhook notification")
		}()
	}
}

// RouteV2RequestPubkey is the handler for /v2/request/pubkey
func (s *Server) RouteV2RequestPubkey(c *gin.Context) {
	// Retrieve the user (which includes the key) from the context
	user := getRequestUserFromCtx(c)
	if user == nil {
		// Should never happen
		AbortWithErrorJSON(c, errors.New("missing request user in context"))
		return
	}

	if user.RequestEncEcdhPubkey == "" || user.RequestEncMlkemPubkey == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "User has not configured request encryption key"))
		return
	}

	// Send the response
	// WrappedKeyEpoch must be the epoch bound into v1 bundle signatures (always PubkeyBundleWrappedKeyEpoch), not the user's live epoch: the bundle is signed once at signup and never re-signed, while the live epoch advances on every password change, which would make the CLI's signature verification fail
	c.JSON(http.StatusOK, v2RequestPubkeyResponse{
		UserID:                       user.ID,
		EcdhP256:                     json.RawMessage(user.RequestEncEcdhPubkey),
		Mlkem768:                     user.RequestEncMlkemPubkey,
		AnchorEs384PublicKey:         user.AnchorEs384PublicKey,
		AnchorMldsa87PublicKey:       user.AnchorMldsa87PublicKey,
		WrappedKeyEpoch:              protocolv2.PubkeyBundleWrappedKeyEpoch,
		PubkeyBundleVersion:          user.PubkeyBundleVersion,
		PubkeyBundleSignatureEs384:   user.PubkeyBundleSignatureEs384,
		PubkeyBundleSignatureMldsa87: user.PubkeyBundleSignatureMldsa87,
	})
}

// RouteV2RequestResult is the handler for GET /v2/request/result/:state
// It's a long-poll: it waits until the request is final, or until the client gives up
func (s *Server) RouteV2RequestResult(c *gin.Context) {
	ctx := c.Request.Context()

	state := c.Param("state")
	if state == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing parameter state"))
		return
	}

	// Get the user from the context, set by the middleware
	user := getRequestUserFromCtx(c)
	if user == nil {
		// Should never happen
		AbortWithErrorJSON(c, errors.New("missing request user in context"))
		return
	}

	// Requests owned by other users live in other actors, so they are reported as missing, and callers can't probe for another user's states
	for i := 0; ; i++ {
		// Register as the request's waiter, which evicts any previous long-poll for the same request
		// Reading the status and registering happen in the same turn, so a change made after this always wakes us
		sub, err := invokeUserActor[userSubscribeRes](ctx, s, user.ID, userMethodSubscribe, userStateReq{State: state})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if !sub.Found {
			// The request may have been collected by another caller while we were waiting
			status := http.StatusNotFound
			if i > 0 {
				status = http.StatusBadRequest
			}
			AbortWithErrorJSON(c, NewResponseError(status, "State not found or expired"))
			return
		}

		if sub.Status.IsTerminal() {
			s.sendRequestResult(c, user.ID, state)
			return
		}

		// Pending: wait until the request changes, another long-poll evicts us, or the client disconnects
		reason, err := s.waitForRequest(ctx, user.ID, state, sub.Waiter)
		switch {
		case err != nil && ctx.Err() != nil:
			// Context canceled; usually the client has disconnected
			// Send response anyway
			c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			})
			return
		case err != nil:
			AbortWithErrorJSON(c, err)
			return
		case reason == waiterReasonEvicted:
			logging.LogFromContext(ctx).WarnContext(ctx,
				"Long-poll subscription evicted by a newer caller for the same state",
				slog.String("state", state),
				slog.String("user_id", user.ID),
				slog.String("client_ip", c.ClientIP()),
			)
			c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
				State:   state,
				Pending: true,
			})
			return
		}

		// The request changed, so check its status again
	}
}

// waitForRequest waits for the signal that wakes the long-poll registered as waiter, and returns the reason it was woken
// It always removes the waiter before returning
func (s *Server) waitForRequest(ctx context.Context, userID string, state string, waiter string) (string, error) {
	env, err := s.waiters.Wait(ctx, waiterSignalID(state, waiter))
	if err != nil {
		// Remove the waiter, using a separate context because the request's may be canceled
		unsubCtx, unsubCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer unsubCancel()
		_, unsubErr := invokeUserActor[struct{}](unsubCtx, s, userID, userMethodUnsubscribe, userStateReq{
			State:  state,
			Waiter: waiter,
		})
		if unsubErr != nil {
			logging.LogFromContext(ctx).WarnContext(ctx, "Failed to remove long-poll waiter", slog.String("state", state), slog.Any("error", unsubErr))
		}

		return "", err
	}

	// The actor removes the waiter before waking it
	var wake waiterWake
	if env != nil {
		err = env.Decode(&wake)
		if err != nil {
			return "", fmt.Errorf("failed to decode wake-up reason: %w", err)
		}
	}

	return wake.Reason, nil
}

// sendRequestResult collects the result of a final request and sends it as response
func (s *Server) sendRequestResult(c *gin.Context, userID string, state string) {
	// Collecting the result removes the request in the same turn, so only one caller can get it
	res, err := invokeUserActor[userCollectRes](c.Request.Context(), s, userID, userMethodCollect, userStateReq{State: state})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if !res.Found {
		// Another caller collected the result first
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "State not found or expired"))
		return
	}

	switch res.Status {
	case db.V2RequestStatusCompleted:
		var env protocolv2.ResponseEnvelope
		err = json.Unmarshal([]byte(res.EncryptedResult), &env)
		if err != nil {
			AbortWithErrorJSON(c, fmt.Errorf("failed to decode response envelope: %w", err))
			return
		}

		c.JSON(http.StatusOK, protocolv2.RequestResultResponse{
			State:            state,
			Done:             true,
			ResponseEnvelope: &env,
		})
	case db.V2RequestStatusCanceled, db.V2RequestStatusExpired:
		c.JSON(http.StatusConflict, protocolv2.RequestResultResponse{
			State:  state,
			Failed: true,
		})
	default:
		// Should never happen, as collect returns pending requests without removing them
		c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
			State:   state,
			Pending: true,
		})
	}
}

func validateV2CreateBody(op string, body *protocolv2.RequestCreateBody) error {
	// Validate the operation
	switch op {
	case protocolv2.OperationEncrypt,
		protocolv2.OperationDecrypt,
		protocolv2.OperationSign:
		// All good
	default:
		return NewResponseError(http.StatusBadRequest, "Invalid operation")
	}

	// Check required fields and enforce the key-label rules
	// The label is normalized to its canonical lowercase form so it round-trips identically through HKDF info, AAD, and DB rows
	if body.KeyLabel == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'keyLabel'")
	}

	canonicalKeyLabel, ok := protocolv2.NormalizeAndValidateKeyLabel(body.KeyLabel)
	if !ok {
		return NewResponseErrorf(http.StatusBadRequest, "parameter 'keyLabel' must be 1-%d bytes and contain only [A-Za-z0-9_.+-]", protocolv2.MaxKeyLabelLength)
	}
	body.KeyLabel = canonicalKeyLabel

	if body.Algorithm == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'algorithm'")
	}
	if len(body.Algorithm) > 64 {
		return NewResponseError(http.StatusBadRequest, "parameter 'algorithm' cannot be longer than 64 characters")
	}

	// For sign operations, restrict algorithm to supported signing algorithms
	// The match is case-insensitive but the stored value is canonical so downstream consumers (HKDF info, AAD, JWS headers) all see the same bytes
	if op == protocolv2.OperationSign {
		canonical, ok := protocolv2.NormalizeSigningAlgorithm(body.Algorithm)
		if !ok {
			return NewResponseErrorf(http.StatusBadRequest, "unsupported signing algorithm %q", body.Algorithm)
		}

		body.Algorithm = canonical
	}

	// For encrypt/decrypt operations, restrict algorithm to the supported AEAD primitives (case-insensitive)
	if (op == protocolv2.OperationEncrypt || op == protocolv2.OperationDecrypt) && !protocolv2.IsSupportedEncryptionAlgorithm(body.Algorithm) {
		return NewResponseErrorf(http.StatusBadRequest, "unsupported encryption algorithm %q", body.Algorithm)
	}

	// Validate optional note
	if body.Note != "" && !body.ValidateNote() {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' contains invalid characters")
	}
	if len(body.Note) > protocolv2.MaxNoteLength {
		return NewResponseErrorf(http.StatusBadRequest, "parameter 'note' cannot be longer than %d characters", protocolv2.MaxNoteLength)
	}

	// Validate E2EE envelope fields, and normalize all base64 to base64url (no padding)
	if body.RequestEncAlg != protocolv2.TransportAlg {
		return NewResponseError(http.StatusBadRequest, "unsupported requestEncAlg")
	}

	err := body.CliEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "invalid cliEphemeralPublicKey: %v", err)
	}

	mlkemCiphertext, err := utils.DecodeBase64String(body.MlkemCiphertext)
	if err != nil || mlkemCiphertext == nil {
		return NewResponseError(http.StatusBadRequest, "mlkemCiphertext is empty or invalid")
	}
	body.MlkemCiphertext = base64.RawURLEncoding.EncodeToString(mlkemCiphertext)

	encryptedPayloadNonce, err := utils.DecodeBase64String(body.EncryptedPayloadNonce)
	if err != nil || encryptedPayloadNonce == nil {
		return NewResponseError(http.StatusBadRequest, "encryptedPayloadNonce is empty or invalid")
	}
	body.EncryptedPayloadNonce = base64.RawURLEncoding.EncodeToString(encryptedPayloadNonce)

	encryptedPayload, err := utils.DecodeBase64String(body.EncryptedPayload)
	if err != nil || encryptedPayload == nil {
		return NewResponseError(http.StatusBadRequest, "encryptedPayload is empty or invalid")
	}
	if len(encryptedPayload) > protocolv2.MaxEnvelopeCiphertextSize {
		return NewResponseErrorf(http.StatusRequestEntityTooLarge, "encryptedPayload cannot be larger than %d KB", protocolv2.MaxEnvelopeCiphertextSize>>10)
	}
	body.EncryptedPayload = base64.RawURLEncoding.EncodeToString(encryptedPayload)

	return nil
}

// validateEnvelopeCiphertextSize returns an error if the base64-encoded ciphertext of an envelope is larger than allowed
func validateEnvelopeCiphertextSize(field string, ciphertext string) error {
	decoded, err := utils.DecodeBase64String(ciphertext)
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "Invalid %s: invalid ciphertext format", field)
	}
	if len(decoded) > protocolv2.MaxEnvelopeCiphertextSize {
		return NewResponseErrorf(http.StatusRequestEntityTooLarge, "Invalid %s: ciphertext cannot be larger than %d KB", field, protocolv2.MaxEnvelopeCiphertextSize>>10)
	}

	return nil
}

// RouteV2RequestSigningPubkey is the handler for GET /v2/request/signing-pubkey
// It returns the stored public key for a signing key owned by the request-key user
// Query params: label (required), algorithm (optional, defaults to ES256)
// The key is auto-stored by the server after each successful sign operation, so no extra registration step is needed
func (s *Server) RouteV2RequestSigningPubkey(c *gin.Context) {
	// Retrieve the user (which includes the key) from the context
	user := getRequestUserFromCtx(c)
	if user == nil {
		// Should never happen
		AbortWithErrorJSON(c, errors.New("missing request user in context"))
		return
	}

	// Get the label from the query parameter
	keyLabel := c.Query("label")
	if keyLabel == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "missing query parameter 'label'"))
		return
	}

	canonicalLabel, ok := protocolv2.NormalizeAndValidateKeyLabel(keyLabel)
	if !ok {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid label"))
		return
	}

	// Get the algorithm from the query parameter (default is ES256)
	algorithm := c.Query("algorithm")
	if algorithm == "" {
		algorithm = protocolv2.SigningAlgES256
	} else {
		canonical, ok := protocolv2.NormalizeSigningAlgorithm(algorithm)
		if !ok {
			AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "unsupported algorithm"))
			return
		}
		algorithm = canonical
	}

	// Get the key
	rec, err := s.db.SigningKeyStore().GetByUserAndLabel(c.Request.Context(), user.ID, algorithm, canonicalLabel)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "signing key not found; perform a sign operation first to register the key"))
		return
	}

	// Send the response
	// The publication proof is included when the row carries one, so the caller can verify the key against the user's pinned anchor
	c.JSON(http.StatusOK, v2RequestSigningPubkeyResponse{
		ID:                          rec.ID,
		Algorithm:                   rec.Algorithm,
		KeyLabel:                    rec.KeyLabel,
		JWK:                         json.RawMessage(rec.JWK),
		PublicationPayload:          rec.PublicationPayload,
		PublicationSignatureEs384:   rec.PublicationSignatureEs384,
		PublicationSignatureMldsa87: rec.PublicationSignatureMldsa87,
	})
}
