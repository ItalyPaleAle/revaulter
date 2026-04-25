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

// RouteV2RequestCreate is the handler for POST /v2/request/:requestKey/(encrypt|decrypt|sign)
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

		err = s.db.RequestStore().CreateRequest(c.Request.Context(), db.CreateRequestInput{
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

// RouteV2RequestPubkey is the handler for /v2/request/:requestKey/pubkey
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

// RouteV2RequestResult is the handler for GET /v2/request/:requestKey/result/:state
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
		case <-watch:
			// We got a notification so let's restart the loop to retrieve the current state
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

	// Check required fields and enforce length limits
	if body.KeyLabel == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'keyLabel'")
	}
	if len(body.KeyLabel) > 128 {
		return NewResponseError(http.StatusBadRequest, "parameter 'keyLabel' cannot be longer than 128 characters")
	}
	if body.Algorithm == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'algorithm'")
	}
	if len(body.Algorithm) > 64 {
		return NewResponseError(http.StatusBadRequest, "parameter 'algorithm' cannot be longer than 64 characters")
	}

	// For sign operations, restrict algorithm to supported signing algorithms
	if op == protocolv2.OperationSign && !protocolv2.IsSupportedSigningAlgorithm(body.Algorithm) {
		return NewResponseErrorf(http.StatusBadRequest, "unsupported signing algorithm %q", body.Algorithm)
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
