package server

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/requestjwt"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// auditRetention is how long v2_audit_events rows are kept before the recurring prune deletes them
const auditRetention = 30 * 24 * time.Hour

// auditPruneInterval is how often the recurring prune fires
// Implemented as a self-rescheduling deleteEvent on the existing deleteQueue
const auditPruneInterval = 24 * time.Hour

// auditFields is the per-call data the helpers do NOT auto-fill
// Caller-provided context (target/key/credential ids, request state, metadata) goes here
// HTTP-context fields (auth method, actor, request id, IP, UA) are pulled from the gin context by auditEvent / auditEventTx
type auditFields struct {
	EventType    db.EventType
	Outcome      db.AuditOutcome
	TargetUserID string
	SigningKeyID string
	CredentialID string
	RequestState string
	Metadata     json.RawMessage

	// AuthMethod is optional — set it explicitly for the request-key path
	// HTTP helpers default to session auth
	AuthMethod db.AuditAuthMethod

	// ActorUserID overrides the default actor lookup
	// Useful when the handler runs before the session middleware has populated UserID (e.g. login_finish, register_finish), or to record a failure for an unauthenticated attempt
	ActorUserID string
}

// auditEvent writes an audit row outside any transaction
// Use auditEventTx instead when the audit row must commit atomically with a state mutation
func (s *Server) auditEvent(c *gin.Context, f auditFields) {
	in := s.auditInputFromContext(c, f)
	_, err := s.db.AuditStore().Insert(c.Request.Context(), in)
	if err != nil {
		logging.LogFromContext(c.Request.Context()).WarnContext(c.Request.Context(),
			"failed to write audit event",
			slog.Any("error", err),
			slog.String("event_type", string(f.EventType)),
		)

		return
	}

	s.nudgeAuditStream()
}

// auditEventTx writes an audit row inside an existing transaction
// Errors are returned so the surrounding transaction can roll back: this is the right policy for security-critical mutations where a missing audit row would silently degrade history
func (s *Server) auditEventTx(c *gin.Context, tx *db.DbTx, f auditFields) error {
	in := s.auditInputFromContext(c, f)
	_, err := tx.AuditStore().Insert(c.Request.Context(), in)
	if err != nil {
		return err
	}

	s.nudgeAuditStream()

	return nil
}

// auditInputFromContext extracts the actor, auth method, request id, IP, and UA from a gin context and merges them with the caller-provided audit fields
func (s *Server) auditInputFromContext(c *gin.Context, f auditFields) db.AuditEventInput {
	// Default actor: the session-bound user
	// If absent, fall back to the user authenticated by the request credential
	actor := f.ActorUserID
	authMethod := f.AuthMethod

	if actor == "" {
		actor = c.GetString(contextKeyUserID)
		if actor != "" && authMethod == "" {
			authMethod = db.AuditAuthMethodSession
		}
	}

	if actor == "" {
		user := getRequestUserFromCtx(c)
		if user != nil {
			actor = user.ID
			if authMethod == "" {
				authMethod = getRequestAuthMethodFromCtx(c)
			}
			if authMethod == "" {
				authMethod = db.AuditAuthMethodRequestKey
			}
		}
	}

	if authMethod == "" {
		// Handlers that run before any authentication is established (login_finish/register_finish failures) record this explicitly
		// Successful flows reach this function with an actor already attached, so the session/request_key branches above will have set authMethod
		authMethod = db.AuditAuthMethodNone
	}

	requestID := c.GetString("request-id")
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	return db.AuditEventInput{
		EventType:     f.EventType,
		Outcome:       f.Outcome,
		AuthMethod:    authMethod,
		ActorUserID:   optionalString(actor),
		TargetUserID:  optionalString(f.TargetUserID),
		SigningKeyID:  optionalString(f.SigningKeyID),
		CredentialID:  optionalString(f.CredentialID),
		RequestState:  optionalString(f.RequestState),
		HTTPRequestID: optionalString(requestID),
		ClientIP:      optionalString(clientIP),
		UserAgent:     optionalString(userAgent),
		Metadata:      f.Metadata,
	}
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// jsonMetadata marshals the given map as a json.RawMessage suitable for AuditEventInput.Metadata
// Returns nil when marshalling fails
func jsonMetadata(payload map[string]any) json.RawMessage {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return b
}

// requestCreateAuditMetadata builds the metadata payload for request.create audit events
// When the request was authenticated with a JWT, it also records the verified issuer, subject, and token ID, so the audit log shows which workload asked
func requestCreateAuditMetadata(operation, algorithm, keyLabel, note string, claims *requestjwt.Claims) json.RawMessage {
	payload := map[string]any{
		"operation": operation,
		"algorithm": algorithm,
		"keyLabel":  keyLabel,
	}
	if note != "" {
		payload["note"] = note
	}
	if claims != nil {
		// The claims come from the token and aren't length-limited, so truncate them to keep the payload under the audit metadata size limit
		payload["jwtIssuer"] = truncateAuditValue(claims.Issuer)
		payload["jwtSubject"] = truncateAuditValue(claims.Subject)
		if claims.JwtID != "" {
			payload["jwtId"] = truncateAuditValue(claims.JwtID)
		}
	}
	return jsonMetadata(payload)
}

func truncateAuditValue(s string) string {
	const auditMetadataMaxValueLength = 200

	r := []rune(s)
	if len(r) <= auditMetadataMaxValueLength {
		return s
	}

	return string(r[:auditMetadataMaxValueLength]) + "…"
}
