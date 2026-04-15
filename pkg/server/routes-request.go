package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
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

func (s *Server) RouteV2RequestCreate(operation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := config.Get()
		log := logging.LogFromContext(c.Request.Context())
		span := trace.SpanFromContext(c.Request.Context())

		requestKey := c.Param("requestKey")
		if requestKey == "" {
			AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing request key"))
			return
		}

		user, err := s.authStore.GetUserByRequestKey(c.Request.Context(), requestKey)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if user == nil || user.Status != "active" {
			AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request key not found"))
			return
		}
		if !user.Ready {
			AbortWithErrorJSON(c, NewResponseError(http.StatusPreconditionFailed, "User account setup is not complete"))
			return
		}
		if !clientIPAllowed(c.ClientIP(), user.AllowedIPs) {
			AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "This client's IP is not allowed to perform this request"))
			return
		}

		var body protocolv2.RequestCreateBody
		err = c.ShouldBindJSON(&body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request body: %v", err))
			return
		}

		err = validateV2CreateBody(operation, body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request: %v", err))
			return
		}

		timeout := body.GetTimeout()
		if timeout == 0 {
			timeout = cfg.RequestTimeout
		} else if timeout > 24*time.Hour {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request: timeout must not be more than 24 hours"))
			return
		}

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

		err = s.requestStore.CreateRequest(c.Request.Context(), db.CreateRequestInput{
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

		err = s.requestExpiryQueue.Enqueue(requestExpiryEvent{
			State:  state,
			UserID: user.ID,
			TTL:    now.Add(timeout),
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"state":   state,
			"pending": true,
		})
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
				StateId:       state,
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

func (s *Server) RouteV2RequestPubkey(c *gin.Context) {
	requestKey := c.Param("requestKey")
	if requestKey == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing request key"))
		return
	}

	user, err := s.authStore.GetUserByRequestKey(c.Request.Context(), requestKey)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if user == nil || user.Status != "active" || !user.Ready {
		AbortWithErrorJSON(c, NewResponseError(http.StatusNotFound, "Request key not found or user setup is not complete"))
		return
	}
	if user.RequestEncEcdhPubkey == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusPreconditionFailed, "User has not configured request encryption key"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ecdhP256": json.RawMessage(user.RequestEncEcdhPubkey),
		"mlkem768": user.RequestEncMlkemPubkey,
	})
}

func (s *Server) RouteV2RequestResult(c *gin.Context) {
	state := c.Param("state")
	if state == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing parameter state"))
		return
	}

	for {
		rec, err := s.requestStore.GetRequest(c.Request.Context(), state)
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
			c.JSON(http.StatusOK, protocolv2.RequestResultResponse{
				State:            rec.State,
				Done:             true,
				ResponseEnvelope: rec.ResponseEnvelope,
			})
			return
		case db.V2RequestStatusCanceled, db.V2RequestStatusExpired:
			c.JSON(http.StatusConflict, protocolv2.RequestResultResponse{
				State:  rec.State,
				Failed: true,
			})
			return
		}

		// Pending: wait for notification or timeout/disconnect.
		s.lock.Lock()
		watch := s.subscribeState(state)
		s.lock.Unlock()
		select {
		case <-watch:
			s.lock.Lock()
			s.unsubscribeState(state, watch)
			s.lock.Unlock()
			continue
		case <-c.Request.Context().Done():
			s.lock.Lock()
			s.unsubscribeState(state, watch)
			s.lock.Unlock()
			c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
				State:   rec.State,
				Pending: true,
			})
			return
		case <-time.After(250 * time.Millisecond):
			s.lock.Lock()
			s.unsubscribeState(state, watch)
			s.lock.Unlock()
		}
	}
}

func validateV2CreateBody(op string, body protocolv2.RequestCreateBody) error {
	// Validate the operation
	switch op {
	case "encrypt", "decrypt":
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

	// Validate optional note
	if body.Note != "" && !body.ValidateNote() {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' contains invalid characters")
	}
	if len(body.Note) > 40 {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' cannot be longer than 40 characters")
	}

	// Validate E2EE envelope fields
	if body.RequestEncAlg != "ecdh-p256+mlkem768+a256gcm" {
		return NewResponseError(http.StatusBadRequest, "unsupported requestEncAlg")
	}
	err := body.CliEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return NewResponseErrorf(http.StatusBadRequest, "invalid cliEphemeralPublicKey: %v", err)
	}
	if body.MlkemCiphertext == "" {
		return NewResponseError(http.StatusBadRequest, "missing mlkemCiphertext")
	}
	_, err = utils.DecodeBase64String(body.MlkemCiphertext)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid mlkemCiphertext format")
	}
	if body.EncryptedPayloadNonce == "" {
		return NewResponseError(http.StatusBadRequest, "missing encryptedPayloadNonce")
	}
	_, err = utils.DecodeBase64String(body.EncryptedPayloadNonce)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid encryptedPayloadNonce format")
	}
	if body.EncryptedPayload == "" {
		return NewResponseError(http.StatusBadRequest, "missing encryptedPayload")
	}
	_, err = utils.DecodeBase64String(body.EncryptedPayload)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid encryptedPayload format")
	}

	return nil
}

func parseRequestTimeout(raw string) time.Duration {
	cfg := config.Get()

	if raw == "" {
		return cfg.RequestTimeout
	}

	rawInt, err := strconv.Atoi(raw)
	if err == nil && rawInt > 0 {
		return time.Duration(rawInt) * time.Second
	}

	d, err := time.ParseDuration(raw)
	if err == nil && d >= time.Second {
		return d
	}

	return cfg.RequestTimeout
}
