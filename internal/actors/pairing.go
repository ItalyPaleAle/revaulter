package actors

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/italypaleale/francis/actor"

	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/protocolv2"
)

const (
	// actorTypePairing is the actor type that holds a user's device pairing session, keyed by user ID
	// A user has at most one session, so opening a new one replaces the previous one
	actorTypePairing = "revaulter.pairing"
	// pairingActorCleanupAlarm is the name of the alarm that deletes a session once it's no longer needed
	pairingActorCleanupAlarm = "cleanup"
	// pairingActorIdleTimeout is how long a pairing actor stays in memory after its last call
	pairingActorIdleTimeout = time.Minute
	// pairingRetention is how long a session is kept after it expires, so both clients can still read its final status
	pairingRetention = 10 * time.Minute
	// maxPairingUserIDLength is the maximum length of a user ID sent by a client
	maxPairingUserIDLength = 128
)

// Methods of the revaulter.pairing actor
const (
	pairingMethodCreate   = "create"
	pairingMethodHello    = "hello"
	pairingMethodNonce    = "nonce"
	pairingMethodComplete = "complete"
	pairingMethodCancel   = "cancel"
	pairingMethodGet      = "get"
)

var (
	// ErrPairingSessionNotFound is returned when the user has no pairing session, or it has a different ID
	ErrPairingSessionNotFound = errors.New("pairing session not found")
	// ErrPairingSessionState is returned when a session is expired, has ended, or isn't at the step the operation needs
	ErrPairingSessionState = errors.New("pairing session is expired or not in the expected state")
)

// PairingSession is a session that relays the pairing messages between a client that is already signed in and a new device
type PairingSession struct {
	// ID of the session, base64url of protocolv2.PairingSessionIDSize random bytes
	// It's the new device's capability for the session, as the device has no other credential
	SessionID string
	UserID    string
	// One of the protocolv2.PairingStatus* values, except PairingStatusExpired, which is never stored
	Status string
	// Base URL the existing client put in the pairing payload
	Server string
	// The new device's hello, once it has sent it
	Hello *protocolv2.PairingHello
	// The existing client's nonce and its MAC, once it has accepted the hello
	Nonce     string
	NonceMAC  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsOpen returns true if the session is still in progress at the given time
func (p PairingSession) IsOpen(now time.Time) bool {
	switch p.Status {
	case protocolv2.PairingStatusCreated, protocolv2.PairingStatusHello, protocolv2.PairingStatusNonce:
		return !now.After(p.ExpiresAt)
	default:
		return false
	}
}

// ReportedStatus returns the status to report to the clients, which is protocolv2.PairingStatusExpired for a session that expired before it ended
func (p PairingSession) ReportedStatus(now time.Time) string {
	switch p.Status {
	case protocolv2.PairingStatusCompleted, protocolv2.PairingStatusCanceled:
		return p.Status
	}

	if !p.IsOpen(now) {
		return protocolv2.PairingStatusExpired
	}

	return p.Status
}

// pairingErrorCode is returned by the revaulter.pairing actor when an operation can't be performed
// These are returned as part of the response rather than as errors, so they reach the caller the same way whether the actor ran locally or on another replica
type pairingErrorCode string

const (
	pairingErrNotFound pairingErrorCode = "not-found"
	pairingErrState    pairingErrorCode = "state"
	// #nosec G101 -- This is an error code, not a credential
	pairingErrCredentialExists pairingErrorCode = "credential-exists"
	pairingErrEpochChanged     pairingErrorCode = "epoch-changed"
	pairingErrUserNotFound     pairingErrorCode = "user-not-found"
)

type pairingCreateReq struct {
	Session PairingSession
	// Audit event to write with the new session, if any
	Audit *db.AuditEventInput
}

type pairingHelloReq struct {
	SessionID string
	Hello     protocolv2.PairingHello
	Audit     *db.AuditEventInput
}

type pairingNonceReq struct {
	SessionID string
	Nonce     string
	NonceMAC  string
}

type pairingCompleteReq struct {
	SessionID string
	// The device credential to add, which must be the one from the session's hello
	Credential db.AddCredentialInput
	Audit      *db.AuditEventInput
}

type pairingCancelReq struct {
	SessionID string
	Audit     *db.AuditEventInput
}

type pairingGetRes struct {
	Found   bool
	Session PairingSession
}

type pairingRes struct {
	Error   pairingErrorCode
	Session PairingSession
}

// pairingActor is the revaulter.pairing actor, which holds a user's pairing session until it's no longer needed
type pairingActor struct {
	host   *Host
	log    *slog.Logger
	client actor.Client[PairingSession]
}

// newPairingActor is the factory for revaulter.pairing actors
func (h *Host) newPairingActor(actorID string, service *actor.Service) actor.Actor {
	return &pairingActor{
		host: h,
		log: h.log.With(
			slog.String("actorType", actorTypePairing),
			slog.String("actorId", actorID),
		),
		client: wrapActorClient(
			actorTypePairing, actorID,
			actor.NewActorClient[PairingSession](actorTypePairing, actorID, service),
		),
	}
}

// Invoke implements actor.ActorInvoke
func (a *pairingActor) Invoke(ctx context.Context, method string, data actor.Envelope) (any, error) {
	switch method {
	case pairingMethodCreate:
		var in pairingCreateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.create(ctx, in)

	case pairingMethodHello:
		var in pairingHelloReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.hello(ctx, in)

	case pairingMethodNonce:
		var in pairingNonceReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.nonce(ctx, in)

	case pairingMethodComplete:
		var in pairingCompleteReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.complete(ctx, in)

	case pairingMethodCancel:
		var in pairingCancelReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.cancel(ctx, in)

	default:
		return nil, fmt.Errorf("unsupported method '%s'", method)
	}
}

// Peek implements actor.ActorPeek
func (a *pairingActor) Peek(ctx context.Context, method string, _ actor.Envelope) (any, error) {
	if method != pairingMethodGet {
		return nil, fmt.Errorf("unsupported method '%s'", method)
	}

	st, err := a.client.GetState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}
	if st.SessionID == "" {
		return pairingGetRes{}, nil
	}

	return pairingGetRes{
		Found:   true,
		Session: st,
	}, nil
}

// Alarm implements actor.ActorAlarm
func (a *pairingActor) Alarm(ctx context.Context, name string, _ actor.Envelope) error {
	if name != pairingActorCleanupAlarm {
		a.log.WarnContext(ctx, "Ignoring unknown alarm", slog.String("alarm", name))
		return nil
	}

	// A session replaced after this alarm was set has a later expiry
	st, err := a.client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	if st.SessionID != "" && time.Now().Before(st.ExpiresAt.Add(pairingRetention)) {
		return a.client.SetAlarm(ctx, pairingActorCleanupAlarm, actor.AlarmProperties{DueTime: st.ExpiresAt.Add(pairingRetention)})
	}

	err = a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		// Re-arm instead of returning an error, since Francis deletes an alarm once its retries run out
		a.log.WarnContext(ctx, "Failed to delete expired pairing session; will retry", slog.Any("error", err))
		return a.client.SetAlarm(ctx, pairingActorCleanupAlarm, actor.AlarmProperties{DueTime: time.Now().Add(time.Minute)})
	}

	return nil
}

// save stores the state
func (a *pairingActor) save(ctx context.Context, st PairingSession) error {
	err := a.client.SetState(ctx, st, nil)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// load returns the session if it has the given ID, or the error code to return
// When status isn't empty, the session must also still be in progress, at that status
func (a *pairingActor) load(ctx context.Context, sessionID string, status string) (PairingSession, pairingErrorCode, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return PairingSession{}, "", fmt.Errorf("failed to load state: %w", err)
	}

	// The session ID is the new device's capability, so compare it in constant time
	if st.SessionID == "" || subtle.ConstantTimeCompare([]byte(st.SessionID), []byte(sessionID)) != 1 {
		return PairingSession{}, pairingErrNotFound, nil
	}

	if status != "" && (st.Status != status || !st.IsOpen(time.Now())) {
		return PairingSession{}, pairingErrState, nil
	}

	return st, "", nil
}

// writeAudit writes an audit event outside of a transaction, if there's one
func (a *pairingActor) writeAudit(ctx context.Context, audit *db.AuditEventInput) error {
	if audit == nil {
		return nil
	}

	_, err := a.host.db.AuditStore().Insert(ctx, *audit)
	if err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}
	a.host.NudgeAuditStream()

	return nil
}

// create stores a new session, replacing any previous one, and sets the cleanup alarm
func (a *pairingActor) create(ctx context.Context, in pairingCreateReq) (pairingRes, error) {
	err := a.writeAudit(ctx, in.Audit)
	if err != nil {
		return pairingRes{}, err
	}

	// Set the alarm first, so a stored session always has one
	err = a.client.SetAlarm(ctx, pairingActorCleanupAlarm, actor.AlarmProperties{DueTime: in.Session.ExpiresAt.Add(pairingRetention)})
	if err != nil {
		return pairingRes{}, fmt.Errorf("failed to set cleanup alarm: %w", err)
	}

	st := in.Session
	st.Status = protocolv2.PairingStatusCreated
	st.Hello = nil
	st.Nonce = ""
	st.NonceMAC = ""
	err = a.save(ctx, st)
	if err != nil {
		return pairingRes{}, err
	}

	return pairingRes{Session: st}, nil
}

// hello stores the new device's hello, once per session
func (a *pairingActor) hello(ctx context.Context, in pairingHelloReq) (pairingRes, error) {
	st, code, err := a.load(ctx, in.SessionID, protocolv2.PairingStatusCreated)
	if err != nil || code != "" {
		return pairingRes{Error: code}, err
	}

	err = a.writeAudit(ctx, in.Audit)
	if err != nil {
		return pairingRes{}, err
	}

	hello := in.Hello
	st.Hello = &hello
	st.Status = protocolv2.PairingStatusHello
	err = a.save(ctx, st)
	if err != nil {
		return pairingRes{}, err
	}

	return pairingRes{Session: st}, nil
}

// nonce stores the existing client's nonce and its MAC, once per session, after the hello
func (a *pairingActor) nonce(ctx context.Context, in pairingNonceReq) (pairingRes, error) {
	st, code, err := a.load(ctx, in.SessionID, protocolv2.PairingStatusHello)
	if err != nil || code != "" {
		return pairingRes{Error: code}, err
	}

	st.Nonce = in.Nonce
	st.NonceMAC = in.NonceMAC
	st.Status = protocolv2.PairingStatusNonce
	err = a.save(ctx, st)
	if err != nil {
		return pairingRes{}, err
	}

	return pairingRes{Session: st}, nil
}

// complete adds the device credential to the main database, together with the audit event, and closes the session
// This runs in a single turn, so a session can add one credential only
func (a *pairingActor) complete(ctx context.Context, in pairingCompleteReq) (pairingRes, error) {
	st, code, err := a.load(ctx, in.SessionID, protocolv2.PairingStatusNonce)
	if err != nil || code != "" {
		return pairingRes{Error: code}, err
	}

	// The credential must be the device from the session's hello, for the session's user
	cred := in.Credential
	if st.Hello == nil || cred.CredentialType != protocolv2.CredentialTypeDevice || cred.UserID != st.UserID || cred.CredentialID != st.Hello.CredentialID {
		return pairingRes{}, errors.New("the credential doesn't match the pairing session")
	}

	_, err = db.ExecuteInTransaction(ctx, a.host.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.AuthStore().AddCredential(ctx, cred)
		if rErr != nil {
			return struct{}{}, rErr
		}

		if in.Audit != nil {
			_, rErr = tx.AuditStore().Insert(ctx, *in.Audit)
			if rErr != nil {
				return struct{}{}, rErr
			}
		}

		return struct{}{}, nil
	})
	switch {
	case errors.Is(err, db.ErrCredentialAlreadyExists):
		return pairingRes{Error: pairingErrCredentialExists}, nil
	case errors.Is(err, db.ErrWrappedKeyEpochChanged):
		return pairingRes{Error: pairingErrEpochChanged}, nil
	case errors.Is(err, db.ErrUserNotFound):
		return pairingRes{Error: pairingErrUserNotFound}, nil
	case err != nil:
		return pairingRes{}, err
	}
	if in.Audit != nil {
		a.host.NudgeAuditStream()
	}

	// The credential is in the main database now
	// If this fails, the session stays at the nonce step until it expires, and a repeated completion reports that the credential exists
	st.Status = protocolv2.PairingStatusCompleted
	err = a.save(ctx, st)
	if err != nil {
		a.log.WarnContext(ctx, "Failed to save completed pairing session", slog.Any("error", err))
	}

	return pairingRes{Session: st}, nil
}

// cancel ends a session that is still in progress
func (a *pairingActor) cancel(ctx context.Context, in pairingCancelReq) (pairingRes, error) {
	st, code, err := a.load(ctx, in.SessionID, "")
	if err != nil || code != "" {
		return pairingRes{Error: code}, err
	}
	if !st.IsOpen(time.Now()) {
		return pairingRes{Error: pairingErrState}, nil
	}

	err = a.writeAudit(ctx, in.Audit)
	if err != nil {
		return pairingRes{}, err
	}

	st.Status = protocolv2.PairingStatusCanceled
	err = a.save(ctx, st)
	if err != nil {
		return pairingRes{}, err
	}

	return pairingRes{Session: st}, nil
}

// PairingClient calls the revaulter.pairing actor of a user
type PairingClient struct {
	host   *Host
	userID string
}

// Pairing returns a client for the revaulter.pairing actor of a user
func (h *Host) Pairing(userID string) PairingClient {
	return PairingClient{
		host:   h,
		userID: userID,
	}
}

// validID returns true if the user ID can be used as an actor ID
func (c PairingClient) validID() bool {
	return c.userID != "" && len(c.userID) <= maxPairingUserIDLength && !strings.ContainsRune(c.userID, '/')
}

// NewPairingSessionID returns a new random session ID
func NewPairingSessionID() (string, error) {
	idBytes := make([]byte, protocolv2.PairingSessionIDSize)
	_, err := rand.Read(idBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(idBytes), nil
}

// Create opens a new session for the user with the ID from NewPairingSessionID, replacing any previous one, and writes the audit event, which is optional
// The session expires after ttl
func (c PairingClient) Create(ctx context.Context, sessionID string, server string, ttl time.Duration, audit *db.AuditEventInput) (*PairingSession, error) {
	if !c.validID() {
		return nil, errors.New("invalid user ID")
	}
	if sessionID == "" {
		return nil, errors.New("session ID is empty")
	}

	now := time.Now()
	return c.call(ctx, pairingMethodCreate, pairingCreateReq{
		Session: PairingSession{
			SessionID: sessionID,
			UserID:    c.userID,
			Server:    server,
			CreatedAt: now,
			ExpiresAt: now.Add(ttl),
		},
		Audit: audit,
	})
}

// Get returns the user's session if it has the given ID, or nil otherwise
func (c PairingClient) Get(ctx context.Context, sessionID string) (*PairingSession, error) {
	if !c.validID() || sessionID == "" {
		return nil, nil
	}

	res, err := peek[pairingGetRes](ctx, c.host, actorTypePairing, c.userID, pairingMethodGet, nil)
	if err != nil {
		return nil, err
	}
	if !res.Found || subtle.ConstantTimeCompare([]byte(res.Session.SessionID), []byte(sessionID)) != 1 {
		return nil, nil
	}

	return &res.Session, nil
}

// IsOpen returns true if the user has a session in progress
func (c PairingClient) IsOpen(ctx context.Context) (bool, error) {
	if !c.validID() {
		return false, nil
	}

	res, err := peek[pairingGetRes](ctx, c.host, actorTypePairing, c.userID, pairingMethodGet, nil)
	if err != nil {
		return false, err
	}

	return res.Found && res.Session.IsOpen(time.Now()), nil
}

// Hello stores the new device's hello, and writes the audit event, which is optional
// The caller must have verified the hello's signatures over the session's transcript
// It returns ErrPairingSessionNotFound if the user has no session with this ID, and ErrPairingSessionState if the session isn't waiting for a hello
func (c PairingClient) Hello(ctx context.Context, sessionID string, hello protocolv2.PairingHello, audit *db.AuditEventInput) (*PairingSession, error) {
	return c.call(ctx, pairingMethodHello, pairingHelloReq{
		SessionID: sessionID,
		Hello:     hello,
		Audit:     audit,
	})
}

// Nonce stores the existing client's nonce and its MAC
// It returns ErrPairingSessionNotFound if the user has no session with this ID, and ErrPairingSessionState if the session isn't waiting for a nonce
func (c PairingClient) Nonce(ctx context.Context, sessionID string, nonce string, nonceMAC string) (*PairingSession, error) {
	return c.call(ctx, pairingMethodNonce, pairingNonceReq{
		SessionID: sessionID,
		Nonce:     nonce,
		NonceMAC:  nonceMAC,
	})
}

// Complete adds the device credential from the session's hello to the main database, writes the audit event, which is optional, and closes the session
// It returns ErrPairingSessionNotFound or ErrPairingSessionState like Nonce, and db.ErrCredentialAlreadyExists, db.ErrWrappedKeyEpochChanged or db.ErrUserNotFound if the credential can't be added
func (c PairingClient) Complete(ctx context.Context, sessionID string, cred db.AddCredentialInput, audit *db.AuditEventInput) (*PairingSession, error) {
	return c.call(ctx, pairingMethodComplete, pairingCompleteReq{
		SessionID:  sessionID,
		Credential: cred,
		Audit:      audit,
	})
}

// Cancel ends a session that is still in progress, and writes the audit event, which is optional
// It returns ErrPairingSessionNotFound if the user has no session with this ID, and ErrPairingSessionState if the session has already ended
func (c PairingClient) Cancel(ctx context.Context, sessionID string, audit *db.AuditEventInput) (*PairingSession, error) {
	return c.call(ctx, pairingMethodCancel, pairingCancelReq{
		SessionID: sessionID,
		Audit:     audit,
	})
}

func (c PairingClient) call(ctx context.Context, method string, data any) (*PairingSession, error) {
	if !c.validID() {
		return nil, ErrPairingSessionNotFound
	}

	res, err := invoke[pairingRes](ctx, c.host, actorTypePairing, c.userID, method, data)
	if err != nil {
		return nil, err
	}

	switch res.Error {
	case pairingErrNotFound:
		return nil, ErrPairingSessionNotFound
	case pairingErrState:
		return nil, ErrPairingSessionState
	case pairingErrCredentialExists:
		return nil, db.ErrCredentialAlreadyExists
	case pairingErrEpochChanged:
		return nil, db.ErrWrappedKeyEpochChanged
	case pairingErrUserNotFound:
		return nil, db.ErrUserNotFound
	}

	return &res.Session, nil
}
