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

	// The session middleware must have authenticated a user before this handler runs
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	// Query the database
	rs := s.db.RequestStore()
	list, err := rs.ListPending(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusOK, list)
}

func (s *Server) RouteV2APIRequestGet(c *gin.Context) {
	state := c.Param("state")

	// The session middleware must have authenticated a user before this handler runs
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	// Get the key request from the database
	rs := s.db.RequestStore()
	rec, err := rs.GetRequest(c.Request.Context(), state)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Return the same error for missing records and records owned by another user, so the endpoint does not reveal whether a foreign state exists
	if rec == nil || userID != rec.UserID {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	// Encode the request object
	var encReq json.RawMessage
	if rec.EncryptedRequest != "" {
		encReq = json.RawMessage(rec.EncryptedRequest)
	}

	// Respond
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

	// Get the user from the context
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, noSessionResponseError)
		return
	}

	// Parse and validate the request
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

	rs := s.db.RequestStore()

	// Handle cancellation requests
	if req.Cancel {
		// Cancel the request in the database
		// Returns ErrRequestNotModifiable if the request can't be found, if it's not pending, or if it doesn't belong to the current user
		rec, err := rs.CancelRequest(c.Request.Context(), req.State, userID)
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

		// Dequeue from the expiry queue
		err = s.requestExpiryQueue.Dequeue("request-expiry:" + req.State)
		if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
			AbortWithErrorJSON(c, err)
			return
		}

		// Send notification to subscribers
		// TODO: Because this blocks until we get a lock, if this becomes a problem consider using a message queue
		s.lock.Lock()
		s.notifySubscriber(req.State)
		s.lock.Unlock()

		// Respond
		c.JSON(http.StatusOK, v2APICanceledResponse{
			Canceled: true,
		})

		// Publish the list item
		s.publishListItem(&db.V2RequestListItem{
			State:  req.State,
			Status: "removed",
			UserID: rec.UserID,
		})
		return
	}

	// Additional validation for complete requests
	if req.ResponseEnvelope == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Missing responseEnvelope"))
		return
	}
	err = req.ResponseEnvelope.Validate()
	if err != nil {
		AbortWithErrorJSON(c, NewResponseErrorf(http.StatusBadRequest, "Invalid responseEnvelope: %v", err))
		return
	}

	// Complete the request
	// Returns ErrRequestNotModifiable if the request can't be found, if it's not pending, or if it doesn't belong to the current user
	rec, err := rs.CompleteRequest(c.Request.Context(), req.State, userID, *req.ResponseEnvelope)
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

	// Dequeue from the expiry queue
	err = s.requestExpiryQueue.Dequeue("request-expiry:" + req.State)
	if err != nil && !errors.Is(err, eventqueue.ErrProcessorStopped) {
		AbortWithErrorJSON(c, err)
		return
	}

	// Send notification to subscribers
	// TODO: Because this blocks until we get a lock, if this becomes a problem consider using a message queue
	s.lock.Lock()
	s.notifySubscriber(req.State)
	s.lock.Unlock()

	// Respond
	c.JSON(http.StatusOK, v2APIConfirmedResponse{
		Confirmed: true,
	})

	// Publish the list item
	s.publishListItem(&db.V2RequestListItem{
		State:  req.State,
		Status: "removed",
		UserID: rec.UserID,
	})
}

func (s *Server) autoStoreSigningKey(c *gin.Context, log *slog.Logger, rec *db.V2RequestRecord, pub *confirmPublicKey) {
	// Validate the key
	id, canonicalJWK, err := validateSigningJWKAndPEM(pub.JWK, pub.PEM)
	if err != nil {
		log.WarnContext(c.Request.Context(), "Skipping auto-store of signing public key: invalid payload",
			slog.String("state", rec.State),
			slog.Any("err", err),
		)
		return
	}

	// Auto-stored keys always land as Published=false so they appear in the settings UI but aren't served from the public fetch endpoint until the user publishes them
	// AutoStoreUnpublished overwrites an existing unpublished slot for the same (user, algorithm, keyLabel) so a single hostile sign cannot permanently claim the slot under an attacker-controlled thumbprint; once the user publishes a key, the slot is locked and this call is a silent no-op
	sks := s.db.SigningKeyStore()
	inserted, err := sks.AutoStoreUnpublished(c.Request.Context(), db.InsertSigningKeyInput{
		ID:        id,
		UserID:    rec.UserID,
		Algorithm: rec.Algorithm,
		KeyLabel:  rec.KeyLabel,
		JWK:       string(canonicalJWK),
		PEM:       pub.PEM,
		Published: false,
	})
	if errors.Is(err, db.ErrSigningKeyAlreadyExists) {
		// The slot is already published, so the auto-store path leaves it alone
		return
	} else if err != nil {
		// Log the error as warning but do not abort the request
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
	// Get the signed-in user
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	// Honour the session JWT's expiry: once the deadline elapses we close the stream so the client reconnects, hits the session middleware, and gets a 401 that drives it back to sign-in
	// Without this, a long-lived NDJSON connection would keep streaming forever even after the JWT it was opened with expired
	sessionTTL := c.GetInt(contextKeySessionTTL)
	if sessionTTL <= 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Session expired"))
		return
	}
	sessionDeadline := time.After(time.Duration(sessionTTL) * time.Second)

	// List currently-pending items
	rs := s.db.RequestStore()
	list, err := rs.ListPending(c.Request.Context(), userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Set the ndJSON content type and send the headers
	c.Header("Content-Type", ndJSONContentType)
	c.Status(http.StatusOK)

	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)

	// Send out the list of items already pending
	if len(list) > 0 {
		for _, item := range list {
			_ = enc.Encode(item)
		}
	} else {
		// Send an empty message if we haven't sent anything
		_, _ = c.Writer.Write([]byte("{}\n"))
	}

	// Start a subscription to watch for new items
	// Note that items that were received between the time we queried the database and when we subscribe may not show up and will require the user to reload the page; we consider that an acceptable UX
	events, err := s.pubsub.Subscribe()
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	defer s.pubsub.Unsubscribe(events)

	// Flush to the writer right away
	c.Writer.Flush()

	// Batch flushing every 100ms
	const flushDelay = 100 * time.Millisecond
	var (
		flushCh <-chan time.Time
		hasData bool
	)

	// Flush whatever was in the buffer when returning
	defer func() {
		if hasData {
			c.Writer.Flush()
		}
	}()

	// Send events as they come in, until the stream is done or the request ends
	for {
		select {
		case msg, more := <-events:
			// When more is false, the stream is done
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

			// Send the message
			_ = enc.Encode(msg)

			// Schedule a flush if there isn't one already for the batch
			hasData = true
			if flushCh == nil {
				flushCh = time.After(flushDelay)
			}

		case <-flushCh:
			// Flush the data
			if hasData {
				c.Writer.Flush()
				hasData = false
			}
			flushCh = nil

		case <-sessionDeadline:
			// Session expired mid-stream — close so the client reconnects and gets 401 from the session middleware
			return

		case <-c.Request.Context().Done():
			// Request is done
			return
		}
	}
}
