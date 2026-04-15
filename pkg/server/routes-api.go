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

type confirmRequest struct {
	State            string                       `json:"state"`
	Confirm          bool                         `json:"confirm,omitempty"`
	Cancel           bool                         `json:"cancel,omitempty"`
	ResponseEnvelope *protocolv2.ResponseEnvelope `json:"responseEnvelope,omitempty"`
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
	filtered := list[:0]
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
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}
	if !s.authorizeUser(c, rec.UserID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request is not assigned to this user"))
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

	rec, err := s.requestStore.GetRequest(c.Request.Context(), req.State)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if rec == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	if !s.authorizeUser(c, rec.UserID) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusForbidden, "Request is not assigned to this user"))
		return
	}

	if req.Cancel {
		ok, err := s.requestStore.CancelRequest(c.Request.Context(), req.State)
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		} else if !ok {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be canceled"))
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

	ok, err := s.requestStore.CompleteRequest(c.Request.Context(), req.State, *req.ResponseEnvelope)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	} else if !ok {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be confirmed"))
		return
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
			break
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
