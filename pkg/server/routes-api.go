package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/go-kit/eventqueue"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/protocolv2"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

type v2APIRequestDetailResponse struct {
	State            string          `json:"state"`
	Status           string          `json:"status"`
	Operation        string          `json:"operation"`
	UserID           string          `json:"userId"`
	KeyLabel         string          `json:"keyLabel"`
	Algorithm        string          `json:"algorithm"`
	Requestor        string          `json:"requestor"`
	Date             int64           `json:"date"`
	Expiry           int64           `json:"expiry"`
	Note             string          `json:"note"`
	EncryptedRequest json.RawMessage `json:"encryptedRequest"`
}

type v2APICanceledResponse struct {
	Canceled bool `json:"canceled"`
}

type v2APIConfirmedResponse struct {
	Confirmed bool `json:"confirmed"`
}

type confirmPublicKey struct {
	JWK json.RawMessage `json:"jwk"`
	PEM string          `json:"pem"`
}

type confirmRequest struct {
	State            string                       `json:"state"`
	Confirm          bool                         `json:"confirm,omitempty"`
	Cancel           bool                         `json:"cancel,omitempty"`
	ResponseEnvelope *protocolv2.ResponseEnvelope `json:"responseEnvelope,omitempty"`
	PublicKey        *confirmPublicKey            `json:"publicKey,omitempty"`
}

func (s *Server) RouteV2APIList(c *gin.Context) {
	if strings.ToLower(c.GetHeader("accept")) == ndJSONContentType {
		s.routeV2APIListStream(c)
		return
	}

	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		// The session middleware must have authenticated a user before this handler runs
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	list, err := s.requestStore.ListPending(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	filtered := make([]db.V2RequestListItem, 0, len(list))
	for _, item := range list {
		if item.UserID == userID {
			filtered = append(filtered, item)
		}
	}

	c.JSON(http.StatusOK, filtered)
}

func (s *Server) RouteV2APIRequestGet(c *gin.Context) {
	state := c.Param("state")

	rec, err := s.requestStore.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Return the same error for missing records and records owned by another user, so the endpoint does not reveal whether a foreign state exists
	if rec == nil || !s.authorizeUser(c, rec.UserID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	var encReq json.RawMessage
	if rec.EncryptedRequest != "" {
		encReq = json.RawMessage(rec.EncryptedRequest)
	}

	c.JSON(http.StatusOK, v2APIRequestDetailResponse{
		State:            rec.State,
		Status:           string(rec.Status),
		Operation:        rec.Operation,
		UserID:           rec.UserID,
		KeyLabel:         rec.KeyLabel,
		Algorithm:        rec.Algorithm,
		Requestor:        rec.RequestorIP,
		Date:             rec.CreatedAt.Unix(),
		Expiry:           rec.ExpiresAt.Unix(),
		Note:             rec.Note,
		EncryptedRequest: encReq,
	})
}

func (s *Server) RouteV2APIConfirm(c *gin.Context) {
	log := logging.LogFromContext(c.Request.Context())

	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "No session"))
		return
	}

	var req confirmRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
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
		rec, err := s.requestStore.CancelRequest(c.Request.Context(), req.State, userID)
		if errors.Is(err, db.ErrRequestNotModifiable) {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be canceled"))
			return
		} else if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}

		log.InfoContext(c.Request.Context(), "Request canceled",
			slog.String("state", req.State),
			slog.String("user_id", userID),
			slog.String("client_ip", c.ClientIP()),
		)

		err = s.requestExpiryQueue.Dequeue("request-expiry:" + req.State)
		if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
			AbortWithErrorJSON(c, err)
			return
		}

		s.lock.Lock()
		s.notifySubscriber(req.State)
		s.lock.Unlock()

		c.JSON(http.StatusOK, v2APICanceledResponse{
			Canceled: true,
		})
		s.publishListItem(&db.V2RequestListItem{
			State:  req.State,
			Status: "removed",
			UserID: rec.UserID,
		})
		return
	}

	if req.ResponseEnvelope == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing responseEnvelope"))
		return
	}

	err = req.ResponseEnvelope.Validate()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid responseEnvelope: %v", err))
		return
	}

	rec, err := s.requestStore.CompleteRequest(c.Request.Context(), req.State, userID, *req.ResponseEnvelope)
	if errors.Is(err, db.ErrRequestNotModifiable) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be confirmed"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// For sign operations the browser sends the derived public key alongside the encrypted response envelope
	// If the user has not published a key for this (algorithm, keyLabel) yet, store it server-side with published=false so it can be shown in the settings UI
	// The signature was already accepted, so failures here are logged and don't fail the request
	if rec.Operation == "sign" && req.PublicKey != nil {
		s.autoStoreSigningKey(c, log, rec, req.PublicKey)
	}

	log.InfoContext(c.Request.Context(), "Request confirmed",
		slog.String("state", req.State),
		slog.Any("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	err = s.requestExpiryQueue.Dequeue("request-expiry:" + req.State)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	s.lock.Lock()
	s.notifySubscriber(req.State)
	s.lock.Unlock()

	c.JSON(http.StatusOK, v2APIConfirmedResponse{
		Confirmed: true,
	})

	s.publishListItem(&db.V2RequestListItem{
		State:  req.State,
		Status: "removed",
		UserID: rec.UserID,
	})
}

func (s *Server) authorizeUser(c *gin.Context, userID string) bool {
	sessionUserID := c.GetString(contextKeyUserID)
	return sessionUserID != "" && sessionUserID == userID
}

func (s *Server) autoStoreSigningKey(c *gin.Context, log *slog.Logger, rec *db.V2RequestRecord, pub *confirmPublicKey) {
	id, canonicalJWK, err := validateSigningJWKAndPEM(pub.JWK, pub.PEM)
	if err != nil {
		log.WarnContext(c.Request.Context(), "Skipping auto-store of signing public key: invalid payload",
			slog.String("state", rec.State),
			slog.Any("err", err),
		)
		return
	}

	// Auto-stored keys always land as Published=false so they appear in the settings UI but aren't served from the public fetch endpoint until the user publishes them
	inserted, err := s.signingKeyStore.Create(c.Request.Context(), db.InsertSigningKeyInput{
		ID:        id,
		UserID:    rec.UserID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		JWK:       string(canonicalJWK),
		PEM:       pub.PEM,
		Published: false,
	})
	if errors.Is(err, db.ErrSigningKeyAlreadyExists) {
		return
	} else if err != nil {
		log.WarnContext(c.Request.Context(), "Failed to auto-store signing public key",
			slog.String("state", rec.State),
			slog.Any("err", err),
		)
		return
	}

	log.InfoContext(c.Request.Context(), "Auto-stored signing public key",
		slog.String("state", rec.State),
		slog.String("key_id", inserted.ID),
		slog.String("key_label", rec.KeyLabel),
		slog.String("algorithm", rec.Algorithm),
	)
}

func (s *Server) routeV2APIListStream(c *gin.Context) {
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		// Fail closed: require an authenticated session before streaming.
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	list, err := s.requestStore.ListPending(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	c.Header("Content-Type", ndJSONContentType)
	c.Status(http.StatusOK)

	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)

	sent := false
	for _, item := range list {
		if item.UserID == userID {
			_ = enc.Encode(item)
			sent = true
		}
	}

	events, err := s.pubsub.Subscribe()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	defer s.pubsub.Unsubscribe(events)

	if !sent {
		// Send an empty message
		_, _ = c.Writer.Write([]byte("{}\n"))
	}

	c.Writer.Flush()
	flushTicker := time.NewTicker(100 * time.Millisecond)
	defer flushTicker.Stop()

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
			// Every broker message must carry a UserID, and it must match the session user
			if msg.UserID == "" || msg.UserID != userID {
				continue
			}

			_ = enc.Encode(msg)
			hasData = true

		case <-flushTicker.C:
			if hasData {
				c.Writer.Flush()
				hasData = false
			}

		case <-c.Request.Context().Done():
			return
		}
	}
}
