package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
	"github.com/italypaleale/revaulter/internal/utils/logging"
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

// v2RequestListStatusRemoved is the status sent in the list stream for requests that are no longer pending
const v2RequestListStatusRemoved = "removed"

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

	// Get the pending requests from the user's actor
	res, err := peekUserActor[userListRes](c.Request.Context(), s, userID, userMethodList, nil)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// Respond
	c.JSON(http.StatusOK, res.Items)
}

func (s *Server) RouteV2APIRequestGet(c *gin.Context) {
	state := c.Param("state")

	// The session middleware must have authenticated a user before this handler runs
	userID := c.GetString(contextKeyUserID)
	if userID == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Unauthenticated"))
		return
	}

	// Get the request from the user's actor
	// Requests owned by other users live in other actors, so they are reported as missing, and the endpoint does not reveal whether a foreign state exists
	res, err := peekUserActor[userGetRes](c.Request.Context(), s, userID, userMethodGet, userStateReq{State: state})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if !res.Found {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	// The envelope is stored in the database
	payload, err := s.db.RequestPayloadStore().Get(c.Request.Context(), state, userID)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if payload == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "State not found or expired"))
		return
	}

	// Encode the request object
	var encReq json.RawMessage
	if payload.EncryptedRequest != "" {
		encReq = json.RawMessage(payload.EncryptedRequest)
	}

	// Respond
	rec := res.Request
	c.JSON(http.StatusOK, v2APIRequestDetailResponse{
		State:            state,
		Status:           string(rec.Status),
		Operation:        rec.Operation,
		UserID:           userID,
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

	// Handle cancellation requests
	if req.Cancel {
		// The actor cancels the request and writes the audit row, then wakes the long-poll and the list streams
		// Requests that can't be found, are not pending, or belong to another user return the same error
		auditIn := s.auditInputFromContext(c, auditFields{
			EventType:   db.AuditRequestCancel,
			Outcome:     db.AuditOutcomeSuccess,
			AuthMethod:  db.AuditAuthMethodSession,
			ActorUserID: userID,
		})
		res, err := invokeUserActor[userChangeRes](c.Request.Context(), s, userID, userMethodCancel, userChangeReq{
			State: req.State,
			Audit: &auditIn,
		})
		if err != nil {
			AbortWithErrorJSON(c, err)
			return
		}
		if res.Error == userActorErrNotModifiable {
			AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be canceled"))
			return
		}

		log.InfoContext(c.Request.Context(), "Request canceled",
			slog.String("state", req.State),
			slog.String("user_id", userID),
			slog.String("client_ip", c.ClientIP()),
		)

		// Respond
		c.JSON(http.StatusOK, v2APICanceledResponse{
			Canceled: true,
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
	err = validateEnvelopeCiphertextSize("responseEnvelope", req.ResponseEnvelope.Ciphertext)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	envJSON, err := json.Marshal(req.ResponseEnvelope)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}

	// The actor stores the response envelope and writes the audit row, then wakes the long-poll and the list streams
	// Requests that can't be found, are not pending, or belong to another user return the same error
	auditIn := s.auditInputFromContext(c, auditFields{
		EventType:   db.AuditRequestConfirm,
		Outcome:     db.AuditOutcomeSuccess,
		AuthMethod:  db.AuditAuthMethodSession,
		ActorUserID: userID,
	})
	res, err := invokeUserActor[userChangeRes](c.Request.Context(), s, userID, userMethodConfirm, userChangeReq{
		State:           req.State,
		EncryptedResult: string(envJSON),
		Audit:           &auditIn,
	})
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	if res.Error == userActorErrNotModifiable {
		AbortWithErrorJSON(c, NewResponseError(http.StatusConflict, "Request cannot be confirmed"))
		return
	}

	// For sign operations the browser sends the derived public key alongside the encrypted response envelope
	// If the user has not published a key for this (algorithm, keyLabel) yet, store it server-side with published=false so it can be shown in the settings UI
	// The signature was already accepted, so failures here are logged and don't fail the request
	if res.Request.Operation == protocolv2.OperationSign && req.PublicKey != nil {
		s.autoStoreSigningKey(c, log, req.State, userID, res.Request, req.PublicKey)
	}

	log.InfoContext(c.Request.Context(), "Request confirmed",
		slog.String("state", req.State),
		slog.Any("user_id", userID),
		slog.String("client_ip", c.ClientIP()),
	)

	// Respond
	c.JSON(http.StatusOK, v2APIConfirmedResponse{
		Confirmed: true,
	})
}

func (s *Server) autoStoreSigningKey(c *gin.Context, log *slog.Logger, state string, userID string, rec userRequest, pub *confirmPublicKey) {
	// Validate the key
	id, canonicalJWK, err := validateSigningJWKAndPEM(rec.Algorithm, pub.JWK, pub.PEM)
	if err != nil {
		log.WarnContext(c.Request.Context(), "Skipping auto-store of signing public key: invalid payload",
			slog.String("state", state),
			slog.Any("err", err),
		)
		return
	}

	// Auto-stored keys always land as Published=false so they appear in the settings UI but aren't served from the public fetch endpoint until the user publishes them
	// AutoStoreUnpublished overwrites an existing unpublished slot for the same (user, algorithm, keyLabel) so a single hostile sign cannot permanently claim the slot under an attacker-controlled thumbprint
	// Once the user publishes a key, the slot is locked and this call is a silent no-op
	sks := s.db.SigningKeyStore()
	inserted, err := sks.AutoStoreUnpublished(c.Request.Context(), db.InsertSigningKeyInput{
		ID:        id,
		UserID:    userID,
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
			slog.String("state", state),
			slog.Any("err", err),
		)
		return
	}

	log.InfoContext(c.Request.Context(), "Auto-stored signing public key",
		slog.String("state", state),
		slog.String("key_id", inserted.ID),
		slog.String("key_label", rec.KeyLabel),
		slog.String("algorithm", rec.Algorithm),
	)

	// Save the audit log entry
	s.auditEvent(c, auditFields{
		EventType:    db.AuditSigningKeyAutoStore,
		Outcome:      db.AuditOutcomeSuccess,
		AuthMethod:   db.AuditAuthMethodSession,
		ActorUserID:  userID,
		SigningKeyID: inserted.ID,
		RequestState: state,
		Metadata: jsonMetadata(map[string]any{
			"algorithm": rec.Algorithm,
			"keyLabel":  rec.KeyLabel,
		}),
	})
}

func (s *Server) routeV2APIListStream(c *gin.Context) {
	ctx := c.Request.Context()

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
	waitCtx, waitCancel := context.WithTimeout(ctx, time.Duration(sessionTTL)*time.Second)
	defer waitCancel()

	// Get the current pending items and the bell to wait on, read together so no change can slip in between
	snap, err := invokeUserActor[userSnapshotRes](ctx, s, userID, userMethodSnapshot, nil)
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
	seen := make(map[string]struct{}, len(snap.Items))
	if len(snap.Items) > 0 {
		for _, item := range snap.Items {
			seen[item.State] = struct{}{}
			_ = enc.Encode(item)
		}
	} else {
		// Send an empty message if we haven't sent anything
		_, _ = c.Writer.Write([]byte("{}\n"))
	}

	// Flush to the writer right away
	c.Writer.Flush()

	// After a change, wait a bit before reading the list again, so a burst of changes is sent as one batch
	const batchDelay = 100 * time.Millisecond

	// Send changes as they happen, until the session expires or the request ends
	for {
		// Wait for the bell to ring, which means the pending requests changed
		_, err = s.inbox.Wait(waitCtx, snap.Bell)
		if err != nil {
			// The session expired, the client disconnected, or the signal failed
			// If the context isn't done, the client reconnects and starts over
			if waitCtx.Err() == nil {
				logging.LogFromContext(ctx).WarnContext(ctx, "Error waiting for list changes", slog.Any("error", err))
			}
			return
		}

		select {
		case <-time.After(batchDelay):
		case <-waitCtx.Done():
			return
		}

		snap, err = invokeUserActor[userSnapshotRes](waitCtx, s, userID, userMethodSnapshot, nil)
		if err != nil {
			if waitCtx.Err() == nil {
				logging.LogFromContext(ctx).WarnContext(ctx, "Error reading list changes", slog.Any("error", err))
			}
			return
		}

		// Send the requests that are new, and a removal message for those that are gone
		current := make(map[string]struct{}, len(snap.Items))
		var hasData bool
		for _, item := range snap.Items {
			current[item.State] = struct{}{}
			_, ok := seen[item.State]
			if ok {
				continue
			}

			_ = enc.Encode(item)
			hasData = true
		}
		for state := range seen {
			_, ok := current[state]
			if ok {
				continue
			}

			_ = enc.Encode(db.V2RequestListItem{
				State:  state,
				Status: v2RequestListStatusRemoved,
				UserID: userID,
			})
			hasData = true
		}
		seen = current

		if hasData {
			c.Writer.Flush()
		}
	}
}
