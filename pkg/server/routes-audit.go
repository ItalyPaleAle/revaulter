package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/pkg/db"
)

type v2AuditEventResponse struct {
	ID            string             `json:"id"`
	CreatedAt     int64              `json:"createdAt"`
	EventType     db.EventType       `json:"eventType"`
	Outcome       db.AuditOutcome    `json:"outcome"`
	AuthMethod    db.AuditAuthMethod `json:"authMethod"`
	ActorUserID   *string            `json:"actorUserId,omitempty"`
	TargetUserID  *string            `json:"targetUserId,omitempty"`
	SigningKeyID  *string            `json:"signingKeyId,omitempty"`
	CredentialID  *string            `json:"credentialId,omitempty"`
	RequestState  *string            `json:"requestState,omitempty"`
	HTTPRequestID *string            `json:"httpRequestId,omitempty"`
	ClientIP      *string            `json:"clientIp,omitempty"`
	UserAgent     *string            `json:"userAgent,omitempty"`
	Metadata      json.RawMessage    `json:"metadata"`
}

type v2AuditEventsResponse struct {
	Events     []v2AuditEventResponse `json:"events"`
	NextCursor string                 `json:"nextCursor"`
}

// RouteV2APIAuditEvents is the handler for GET /v2/api/audit-events
func (s *Server) RouteV2APIAuditEvents(c *gin.Context) {
	// The session middleware must have authenticated a user before this handler runs
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	// Parse cursor from query params
	cursor := c.Query("cursor")

	var eventType db.EventType
	if c.Query("eventType") != "" {
		eventType = db.EventType(c.Query("eventType"))
		if !eventType.Valid() {
			AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid eventType"))
			return
		}
	}

	// Query the audit store with a filter scoped to the authenticated user
	store := s.db.AuditStore()
	events, nextCursor, err := store.List(c.Request.Context(),
		db.AuditFilter{
			UserID:    userID,
			EventType: eventType,
		},
		50, cursor,
	)
	if errors.Is(err, db.ErrAuditInvalidCursor) {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "invalid cursor"))
		return
	} else if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Map to response DTOs
	out := make([]v2AuditEventResponse, len(events))
	for i, e := range events {
		out[i] = v2AuditEventResponse{
			ID:            e.ID,
			CreatedAt:     e.CreatedAt.Unix(),
			EventType:     e.EventType,
			Outcome:       e.Outcome,
			AuthMethod:    e.AuthMethod,
			ActorUserID:   e.ActorUserID,
			TargetUserID:  e.TargetUserID,
			SigningKeyID:  e.SigningKeyID,
			CredentialID:  e.CredentialID,
			RequestState:  e.RequestState,
			HTTPRequestID: e.HTTPRequestID,
			ClientIP:      e.ClientIP,
			UserAgent:     e.UserAgent,
			Metadata:      e.Metadata,
		}
	}

	// Send the response
	c.JSON(http.StatusOK, v2AuditEventsResponse{
		Events:     out,
		NextCursor: nextCursor,
	})
}
