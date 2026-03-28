package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
	"github.com/italypaleale/revaulter/pkg/v2db"
)

var noteValidate = regexp.MustCompile(`[^A-Za-z0-9 .\/_-]`)

type confirmRequest struct {
	State            string                       `json:"state"`
	Confirm          bool                         `json:"confirm,omitempty"`
	Cancel           bool                         `json:"cancel,omitempty"`
	ResponseEnvelope *protocolv2.ResponseEnvelope `json:"responseEnvelope,omitempty"`
}

func (s *Server) RouteV2RequestCreate(operation string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := logging.LogFromContext(c.Request.Context())
		span := trace.SpanFromContext(c.Request.Context())

		if s.requestStore == nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
			return
		}

		var body protocolv2.RequestCreateBody
		err := c.ShouldBindJSON(&body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request body: %v", err))
			return
		}

		err = validateV2CreateBody(operation, body)
		if err != nil {
			AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid request: %v", err))
			return
		}

		timeout := parseV2Timeout(body.Timeout)
		now := time.Now()
		id, err := uuid.NewRandom()
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		state := id.String()

		err = s.requestStore.CreateRequest(c.Request.Context(), v2db.CreateRequestInput{
			State:       state,
			Operation:   operation,
			RequestorIP: c.ClientIP(),
			CreatedAt:   now,
			ExpiresAt:   now.Add(timeout),
			Body:        body,
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"state":   state,
			"pending": true,
		})
		s.publishV2ListItem(&v2db.V2RequestListItem{
			State:      state,
			Status:     string(v2db.V2RequestStatusPending),
			Operation:  operation,
			TargetUser: body.TargetUser,
			KeyLabel:   body.KeyLabel,
			Algorithm:  body.Algorithm,
			Requestor:  c.ClientIP(),
			Date:       now.Unix(),
			Expiry:     now.Add(timeout).Unix(),
			Note:       body.Note,
		})

		// Notify admins via webhook in background
		go func() {
			// Use a background context because the request's context is canceled when the handler returns
			webhookCtx := trace.ContextWithSpan(context.Background(), span)
			webhookErr := s.webhook.SendWebhook(webhookCtx, &webhook.WebhookRequest{
				Flow:          "v2",
				OperationName: operation,
				TargetUser:    body.TargetUser,
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

func (s *Server) RouteV2RequestResult(c *gin.Context) {
	if s.requestStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
		return
	}
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
		case v2db.V2RequestStatusCompleted:
			c.JSON(http.StatusOK, protocolv2.RequestResultResponse{
				State:            rec.State,
				Done:             true,
				ResponseEnvelope: rec.ResponseEnvelope,
			})
			return
		case v2db.V2RequestStatusCanceled, v2db.V2RequestStatusExpired:
			c.JSON(http.StatusConflict, protocolv2.RequestResultResponse{
				State:  rec.State,
				Failed: true,
			})
			return
		}

		// Pending: wait for notification or timeout/disconnect.
		s.lock.Lock()
		watch := s.subscribeToV2State(state)
		s.lock.Unlock()
		select {
		case <-watch:
			s.lock.Lock()
			s.unsubscribeToV2State(state, watch)
			s.lock.Unlock()
			continue
		case <-c.Request.Context().Done():
			s.lock.Lock()
			s.unsubscribeToV2State(state, watch)
			s.lock.Unlock()
			c.JSON(http.StatusAccepted, protocolv2.RequestResultResponse{
				State:   rec.State,
				Pending: true,
			})
			return
		case <-time.After(250 * time.Millisecond):
			s.lock.Lock()
			s.unsubscribeToV2State(state, watch)
			s.lock.Unlock()
		}
	}
}

func (s *Server) RouteV2APIList(c *gin.Context) {
	if s.requestStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
		return
	}
	if strings.ToLower(c.GetHeader("accept")) == ndJSONContentType {
		s.routeV2APIListStream(c)
		return
	}

	list, err := s.requestStore.ListPending(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	username, _ := c.Get(contextKeyAdminUsername)
	userStr, _ := username.(string)
	if userStr != "" {
		filtered := list[:0]
		for _, item := range list {
			if item.TargetUser == userStr {
				filtered = append(filtered, item)
			}
		}
		list = filtered
	}
	c.JSON(http.StatusOK, list)
}

func (s *Server) RouteV2APIRequestGet(c *gin.Context) {
	if s.requestStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
		return
	}
	state := c.Param("state")
	rec, err := s.requestStore.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}
	if !s.v2AuthorizeTargetUser(c, rec.TargetUser) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request is not assigned to this user"))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"state":      rec.State,
		"status":     rec.Status,
		"operation":  rec.Operation,
		"targetUser": rec.TargetUser,
		"keyLabel":   rec.KeyLabel,
		"algorithm":  rec.Algorithm,
		"requestor":  rec.RequestorIP,
		"date":       rec.CreatedAt.Unix(),
		"expiry":     rec.ExpiresAt.Unix(),
		"note":       rec.Note,
		"request":    rec.RequestBody,
	})
}

func (s *Server) RouteV2APIConfirm(c *gin.Context) {
	if s.requestStore == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusServiceUnavailable, "database is not configured"))
		return
	}
	var req confirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Invalid request body"))
		return
	}
	if req.State == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing state in request body"))
		return
	}
	if (req.Confirm && req.Cancel) || (!req.Confirm && !req.Cancel) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "One and only one of confirm and cancel must be set to true in the body"))
		return
	}

	if req.Cancel {
		rec, err := s.requestStore.GetRequest(c.Request.Context(), req.State)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if rec == nil {
			AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
			return
		}
		if !s.v2AuthorizeTargetUser(c, rec.TargetUser) {
			AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request is not assigned to this user"))
			return
		}
		ok, err := s.requestStore.CancelRequest(c.Request.Context(), req.State)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if !ok {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be canceled"))
			return
		}
		s.lock.Lock()
		s.notifyV2Subscriber(req.State)
		s.lock.Unlock()
		c.JSON(http.StatusOK, gin.H{"canceled": true})
		s.publishV2ListItem(&v2db.V2RequestListItem{
			State:  req.State,
			Status: "removed",
		})
		return
	}

	if req.ResponseEnvelope == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing responseEnvelope"))
		return
	}
	if err := validateV2ResponseEnvelope(*req.ResponseEnvelope); err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid responseEnvelope: %v", err))
		return
	}
	rec, err := s.requestStore.GetRequest(c.Request.Context(), req.State)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}
	if !s.v2AuthorizeTargetUser(c, rec.TargetUser) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request is not assigned to this user"))
		return
	}
	if err := validateV2ResponseEnvelopeBinding(*req.ResponseEnvelope, rec); err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid responseEnvelope binding: %v", err))
		return
	}
	ok, err := s.requestStore.CompleteRequest(c.Request.Context(), req.State, *req.ResponseEnvelope)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if !ok {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be confirmed"))
		return
	}
	s.lock.Lock()
	s.notifyV2Subscriber(req.State)
	s.lock.Unlock()
	c.JSON(http.StatusOK, gin.H{"confirmed": true})
	s.publishV2ListItem(&v2db.V2RequestListItem{
		State:  req.State,
		Status: "removed",
	})
}

func validateV2ResponseEnvelopeBinding(env protocolv2.ResponseEnvelope, rec *v2db.V2RequestRecord) error {
	if rec == nil {
		return NewResponseError(http.StatusBadRequest, "request is missing")
	}
	if env.AAD == "" {
		return nil
	}
	aadRaw, err := utils.DecodeBase64String(env.AAD)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid aad format")
	}
	type transportAAD struct {
		V         int    `json:"v"`
		State     string `json:"state"`
		Operation string `json:"operation"`
		Algorithm string `json:"algorithm"`
	}
	var aad transportAAD
	dec := json.NewDecoder(bytes.NewReader(aadRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&aad); err != nil {
		return nil
	}
	if aad.V != 0 && aad.V != 1 {
		return NewResponseError(http.StatusBadRequest, "unsupported aad version")
	}
	if aad.State != "" && aad.State != rec.State {
		return NewResponseError(http.StatusBadRequest, "aad state mismatch")
	}
	if aad.Operation != "" && aad.Operation != rec.Operation {
		return NewResponseError(http.StatusBadRequest, "aad operation mismatch")
	}
	if aad.Algorithm != "" && aad.Algorithm != rec.Algorithm {
		return NewResponseError(http.StatusBadRequest, "aad algorithm mismatch")
	}
	return nil
}

func (s *Server) v2AuthorizeTargetUser(c *gin.Context, targetUser string) bool {
	usernameAny, ok := c.Get(contextKeyAdminUsername)
	if !ok {
		return false
	}
	username, ok := usernameAny.(string)
	if !ok {
		return false
	}
	return username != "" && username == targetUser
}

func validateV2CreateBody(op string, body protocolv2.RequestCreateBody) error {
	// Validate the operation
	switch op {
	case "encrypt", "decrypt":
	default:
		return NewResponseError(http.StatusBadRequest, "Invalid operation")
	}

	// Check required fields
	if body.TargetUser == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'targetUser'")
	}
	if body.KeyLabel == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'keyLabel'")
	}
	if body.Algorithm == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'algorithm'")
	}
	if body.Value == "" {
		return NewResponseError(http.StatusBadRequest, "missing parameter 'value'")
	}

	// Validate base64-encoded fields
	_, err := utils.DecodeBase64String(body.Value)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid 'value' format")
	}
	_, err = utils.DecodeBase64String(body.Nonce)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid 'nonce' format")
	}
	_, err = utils.DecodeBase64String(body.Tag)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid 'tag' format")
	}
	_, err = utils.DecodeBase64String(body.AdditionalData)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid 'additionalData' format")
	}

	// Validate optional note
	if body.Note != "" && noteValidate.MatchString(body.Note) {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' contains invalid characters")
	}
	if len(body.Note) > 40 {
		return NewResponseError(http.StatusBadRequest, "parameter 'note' cannot be longer than 40 characters")
	}

	// Validate the client transport key
	err = body.ClientTransportKey.ValidatePublic()
	if err != nil {
		return err
	}

	return nil
}

func validateV2ResponseEnvelope(env protocolv2.ResponseEnvelope) error {
	// Currently only supported transport algorithm is ECDH+P-256 with AES-256-GCM
	if env.TransportAlg != "ecdh-p256+a256gcm" {
		return NewResponseError(http.StatusBadRequest, "unsupported transportAlg")
	}

	// Validate the browser's ephemeral public key
	err := env.BrowserEphemeralPublicKey.ValidatePublic()
	if err != nil {
		return err
	}

	// Validate required fields
	if env.Nonce == "" || env.Ciphertext == "" {
		return NewResponseError(http.StatusBadRequest, "nonce and ciphertext are required")
	}

	// Validate base64-encoded fields
	_, err = utils.DecodeBase64String(env.Nonce)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid nonce format")
	}
	_, err = utils.DecodeBase64String(env.Ciphertext)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid ciphertext format")
	}
	_, err = utils.DecodeBase64String(env.AAD)
	if err != nil {
		return NewResponseError(http.StatusBadRequest, "invalid aad format")
	}
	return nil
}

func parseV2Timeout(raw string) time.Duration {
	if raw == "" {
		return config.Get().RequestTimeout
	}
	if rawInt, err := strconv.Atoi(raw); err == nil && rawInt > 0 {
		return time.Duration(rawInt) * time.Second
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= time.Second {
		return d
	}
	return config.Get().RequestTimeout
}

func (s *Server) routeV2APIListStream(c *gin.Context) {
	list, err := s.requestStore.ListPending(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	usernameAny, _ := c.Get(contextKeyAdminUsername)
	username, _ := usernameAny.(string)

	c.Header("content-type", ndJSONContentType)
	c.Status(http.StatusOK)
	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)
	sent := false
	known := map[string]v2db.V2RequestListItem{}
	for _, item := range list {
		if username != "" && item.TargetUser != username {
			continue
		}
		_ = enc.Encode(item)
		known[item.State] = item
		sent = true
	}
	events, err := s.v2Pubsub.Subscribe()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	defer s.v2Pubsub.Unsubscribe(events)
	if !sent {
		_, _ = c.Writer.Write([]byte{'\n'})
	}
	c.Writer.Flush()
	flushTicker := time.NewTicker(100 * time.Millisecond)
	defer flushTicker.Stop()
	reconcileTicker := time.NewTicker(2 * time.Second)
	defer reconcileTicker.Stop()
	hasData := false
	for {
		select {
		case msg, more := <-events:
			if !more {
				return
			}
			if msg == nil {
				continue
			}
			if username != "" && msg.TargetUser != "" && msg.TargetUser != username {
				continue
			}
			_ = enc.Encode(msg)
			if msg.Status == "removed" {
				delete(known, msg.State)
			} else if msg.State != "" {
				known[msg.State] = *msg
			}
			hasData = true
		case <-flushTicker.C:
			if hasData {
				c.Writer.Flush()
				hasData = false
			}
		case <-reconcileTicker.C:
			curList, err := s.requestStore.ListPending(c.Request.Context())
			if err != nil {
				continue
			}
			current := map[string]v2db.V2RequestListItem{}
			for _, item := range curList {
				if username != "" && item.TargetUser != username {
					continue
				}
				current[item.State] = item
				prev, ok := known[item.State]
				if !ok || !reflect.DeepEqual(prev, item) {
					_ = enc.Encode(item)
					hasData = true
				}
			}
			for state := range known {
				if _, ok := current[state]; !ok {
					_ = enc.Encode(&v2db.V2RequestListItem{State: state, Status: "removed"})
					hasData = true
				}
			}
			known = current
		case <-c.Request.Context().Done():
			return
		}
	}
}
