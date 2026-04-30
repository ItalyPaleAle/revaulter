package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

type v2RequestCreateResponse struct {
	State   string `json:"state"`
	Pending bool   `json:"pending"`
}

// v2RequestSigningPubkeyResponse is the response for GET /v2/request/signing-pubkeys
type v2RequestSigningPubkeyResponse struct {
	ID        string          `json:"id"`
	Algorithm string          `json:"algorithm"`
	KeyLabel  string          `json:"keyLabel"`
	JWK       json.RawMessage `json:"jwk"`
}

type v2RequestPubkeyResponse struct {
	UserID   string          `json:"userId"`
	EcdhP256 json.RawMessage `json:"ecdhP256"`
	Mlkem768 string          `json:"mlkem768"`

	// Hybrid anchor pubkeys + bundle self-signatures. The CLI pins the anchor pubkeys
	// (TOFU) and verifies both signatures over the bundle to detect server-side pubkey
	// substitution attacks.
	AnchorEs384PublicKey         string `json:"anchorEs384PublicKey"`
	AnchorMldsa87PublicKey       string `json:"anchorMldsa87PublicKey"`
	WrappedKeyEpoch              int64  `json:"wrappedKeyEpoch"`
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

		// Save the request in the database
		now := time.Now()
		id, err := uuid.NewRandom()
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		state := id.String()

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

		// Needs to be executed in a transaction for consistency
		_, err = db.ExecuteInTransaction(c.Request.Context(), s.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
			// Store the request in the database
			rErr := tx.RequestStore().CreateRequest(ctx, db.CreateRequestInput{
				State:            state,
				UserID:           user.ID,
				Operation:        operation,
				RequestorIP:      c.ClientIP(),
				KeyLabel:         body.KeyLabel,
				Algorithm:        body.Algorithm,
				Note:             body.Note,
				CreatedAt:        now,
				ExpiresAt:        now.Add(timeout),
				EncryptedRequest: string(encEnvelopeJSON),
			})
			if rErr != nil {
				return struct{}{}, rErr
			}

			// Create the audit log event
			rErr = s.auditEventTx(c, tx, auditFields{
				EventType:    db.AuditRequestCreate,
				Outcome:      db.AuditOutcomeSuccess,
				AuthMethod:   db.AuditAuthMethodRequestKey,
				ActorUserID:  user.ID,
				RequestState: state,
				Metadata: jsonMetadata(map[string]any{
					"operation": operation,
					"algorithm": body.Algorithm,
					"keyLabel":  body.KeyLabel,
				}),
			})
			if rErr != nil {
				return struct{}{}, rErr
			}

			return struct{}{}, nil
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		// Enqueue the request for cleanup when it expires
		err = s.requestExpiryQueue.Enqueue(requestExpiryEvent{
			State:  state,
			UserID: user.ID,
			TTL:    now.Add(timeout + 5*time.Second),
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		// Send response
		c.JSON(http.StatusAccepted, v2RequestCreateResponse{
			State:   state,
			Pending: true,
		})

		// Publish the new item
		s.publishListItem(&db.V2RequestListItem{
			State:     state,
			Status:    string(db.V2RequestStatusPending),
			Operation: operation,
			UserID:    user.ID,
			KeyLabel:  body.KeyLabel,
			Algorithm: body.Algorithm,
			Requestor: c.ClientIP(),
			Date:      now.Unix(),
			Expiry:    now.Add(timeout).Unix(),
			Note:      body.Note,
		})

		// Notify users via webhook in background
		go func() {
			displayName := user.DisplayName
			if displayName == "" {
				displayName = user.ID
			}

			// Use a background context because the request's context is canceled when the handler returns
			webhookCtx := trace.ContextWithSpan(context.Background(), span)
			webhookErr := s.webhook.SendWebhook(webhookCtx, &webhook.WebhookRequest{
				Flow:          "v2",
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
	c.JSON(http.StatusOK, v2RequestPubkeyResponse{
		UserID:                       user.ID,
		EcdhP256:                     json.RawMessage(user.RequestEncEcdhPubkey),
		Mlkem768:                     user.RequestEncMlkemPubkey,
		AnchorEs384PublicKey:         user.AnchorEs384PublicKey,
		AnchorMldsa87PublicKey:       user.AnchorMldsa87PublicKey,
		WrappedKeyEpoch:              user.WrappedKeyEpoch,
		PubkeyBundleSignatureEs384:   user.PubkeyBundleSignatureEs384,
		PubkeyBundleSignatureMldsa87: user.PubkeyBundleSignatureMldsa87,
	})
}

// RouteV2RequestResult is the handler for GET /v2/request/result/:state
func (s *Server) RouteV2RequestResult(c *gin.Context) {
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

	rs := s.db.RequestStore()

	// Initial read to validate ownership before subscribing
	// We must not allow subscriptions to a state the caller doesn't own
	rec, err := rs.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "State not found or expired"))
		return
	}

	// Verify the request belongs to the user identified by the request key
	// Collapse the mismatch into the same error as "not found" so callers can't probe for another user's states
	if rec.UserID != user.ID {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "State not found or expired"))
		return
	}

	// Subscribe now that ownership is verified
	// A single subscription covers the whole long-poll: terminal transitions are final, so notifySubscriber fires at most once per state
	s.lock.Lock()
	watch := s.subscribeState(state)
	s.lock.Unlock()
	defer func() {
		s.lock.Lock()
		s.unsubscribeState(state, watch)
		s.lock.Unlock()
	}()

	for {
		// Re-read on every iteration: closes the race between the ownership read and the subscribe, and reflects state after each wakeup
		// UserID is immutable, so we don't need to re-check ownership
		rec, err = rs.GetRequest(c.Request.Context(), state)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if rec == nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
			return
		}

		switch rec.Status {
		case db.V2RequestStatusCompleted:
			// This method deletes the request only if it's still pending, so it's safe to not use a transaction
			// Besides, thanks to the subscription handling, we get concurrency control anyways
			rec, err = rs.GetAndDeleteTerminalRequest(c.Request.Context(), state)
			if err != nil {
				AbortWithErrorJSON(c, err)
				return
			}
			if rec == nil {
				continue
			}

			// Send response
			c.JSON(http.StatusOK, protocolv2.RequestResultResponse{
				State:            rec.State,
				Done:             true,
				ResponseEnvelope: rec.ResponseEnvelope,
			})
			return
		case db.V2RequestStatusCanceled, db.V2RequestStatusExpired:
			// This method deletes the request only if it's still pending, so it's safe to not use a transaction
			// Besides, thanks to the subscription handling, we get concurrency control anyways
			rec, err = rs.GetAndDeleteTerminalRequest(c.Request.Context(), state)
			if err != nil {
				AbortWithErrorJSON(c, err)
				return
			}
			if rec == nil {
				continue
			}

			// Send response
			c.JSON(http.StatusConflict, protocolv2.RequestResultResponse{
				State:  rec.State,
				Failed: true,
			})
			return
		}

		// Pending: wait for notification or disconnect
		select {
		case _, ok := <-watch:
			// ok is false when subscribeState closed the channel without sending: another caller took over the subscription, so this caller must return
			if !ok {
				// Log the eviction
				logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
					"Long-poll subscription evicted by a newer caller for the same state",
					slog.String("state", state),
					slog.String("user_id", user.ID),
					slog.String("client_ip", c.ClientIP()),
				)
				c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
					State:   rec.State,
					Pending: true,
				})
				return
			}

			// ok is true when notifySubscriber sent a value before closing: a real notification, so re-check the state
			continue
		case <-c.Request.Context().Done():
			// Context canceled; usually the client has disconnected
			// Send response anyway
			c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
				State:   rec.State,
				Pending: true,
			})
			return
		}
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
	if len(body.Note) > 40 {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' cannot be longer than 40 characters")
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
	body.EncryptedPayload = base64.RawURLEncoding.EncodeToString(encryptedPayload)

	return nil
}

// RouteV2RequestSigningPubkey returns the stored public key for a signing key owned by the request-key user
// Query params: label (required), algorithm (optional, defaults to ES256)
// The key is auto-stored by the server after each successful sign operation, so no extra registration step is needed
func (s *Server) RouteV2RequestSigningPubkey(c *gin.Context) {
	user := getRequestUserFromCtx(c)
	if user == nil {
		AbortWithErrorJSON(c, errors.New("missing request user in context"))
		return
	}

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

	rec, err := s.db.SigningKeyStore().GetByUserAndLabel(c.Request.Context(), user.ID, algorithm, canonicalLabel)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "signing key not found; perform a sign operation first to register the key"))
		return
	}

	c.JSON(http.StatusOK, v2RequestSigningPubkeyResponse{
		ID:        rec.ID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		JWK:       json.RawMessage(rec.JWK),
	})
}
