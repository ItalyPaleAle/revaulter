package actors

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/italypaleale/francis/actor"
	"github.com/italypaleale/francis/builtin/signal"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/utils"
)

const (
	// actorTypeUser is the actor type that holds each user's requests, keyed by user ID
	actorTypeUser = "revaulter.user"
	// userActorCleanupAlarm is the name of the alarm that expires and removes a user's requests
	userActorCleanupAlarm = "cleanup"

	// MaxPendingRequestsPerUser caps the number of requests a user can have pending at once
	MaxPendingRequestsPerUser = 50
	// RequestRemoveGrace is how long a finished request is kept after its deadline, so the caller can still collect its result
	RequestRemoveGrace = 10 * time.Minute

	// requestExpiryGrace is added to a request's deadline when scheduling its expiry, so the deadline has passed when the alarm fires
	requestExpiryGrace = 5 * time.Second
	// userActorCleanupRetryDelay is how long the cleanup alarm waits before trying again after a failure
	userActorCleanupRetryDelay = time.Minute
	// userActorDBTimeout is the timeout for the transactions the actor runs on the main database
	userActorDBTimeout = 30 * time.Second
)

// Methods of the revaulter.user actor
const (
	userMethodCreate      = "create"
	userMethodConfirm     = "confirm"
	userMethodCancel      = "cancel"
	userMethodSubscribe   = "subscribe"
	userMethodUnsubscribe = "unsubscribe"
	userMethodCollect     = "collect"
	userMethodSnapshot    = "snapshot"
	userMethodList        = "list"
	userMethodGet         = "get"
	userMethodRepair      = "repair"
	userMethodCheck       = "check"
)

// Reasons sent to the long-poll waiting for the result of a request
const (
	// The request reached a final state
	waiterReasonDone = "done"
	// A newer long-poll for the same request took over
	waiterReasonEvicted = "evicted"
)

// testUserMethods handles the methods of the revaulter.user actor used by the e2e tests, returning false when the method isn't one of them
// This is only set in e2e builds
var testUserMethods func(ctx context.Context, a *userActor, method string, data actor.Envelope) (res any, handled bool, err error)

// userActorErrorCode is returned by the revaulter.user actor when an operation can't be performed
// These are returned as part of the response rather than as errors, so they reach the caller the same way whether the actor ran locally or on another replica
type userActorErrorCode string

const (
	// The request doesn't exist, isn't pending, or is past its deadline
	userActorErrNotModifiable userActorErrorCode = "not-modifiable"
	// The user has too many pending requests
	userActorErrTooManyPending userActorErrorCode = "too-many-pending"
)

// userActorState is the state of a revaulter.user actor
type userActorState struct {
	// Pending and recently finished requests, keyed by request state
	Requests map[string]*Request
	// Signal ID that list streams wait on, replaced on every change to the pending requests
	Bell string
	// Time of the last change to the pending requests
	// When there are no requests left, the bell is kept for one session timeout after this
	LastChange time.Time
}

// clone returns a deep copy of the state, so changes can be discarded if they fail to be saved
func (st userActorState) clone() userActorState {
	res := st
	res.Requests = make(map[string]*Request, len(st.Requests))
	for k, v := range st.Requests {
		res.Requests[k] = new(*v)
	}
	return res
}

// isEmpty returns true if there's nothing in the state
func (st userActorState) isEmpty() bool {
	return len(st.Requests) == 0 && st.Bell == ""
}

// nextCleanup returns when the cleanup alarm must run next: the earliest time a request is due to be expired or removed, or when the bell alone expires
// It returns zero if the state is empty
func (st userActorState) nextCleanup(sessionTimeout time.Duration) time.Time {
	var due time.Time
	for _, r := range st.Requests {
		d := r.cleanupDue()
		if due.IsZero() || d.Before(due) {
			due = d
		}
	}

	if len(st.Requests) == 0 && st.Bell != "" {
		due = st.LastChange.Add(sessionTimeout)
	}

	return due
}

// pendingList returns the pending requests that haven't passed their deadline, oldest first
func (st userActorState) pendingList(userID string, now time.Time) []db.V2RequestListItem {
	var res []db.V2RequestListItem
	for state, r := range st.Requests {
		if r.Status != db.V2RequestStatusPending || r.isOverdue(now) {
			continue
		}

		res = append(res, r.listItem(state, userID))
	}

	slices.SortFunc(res, func(a, b db.V2RequestListItem) int {
		return cmp.Or(
			cmp.Compare(a.Date, b.Date),
			cmp.Compare(a.State, b.State),
		)
	})

	return res
}

// countPending returns the number of pending requests, including those past their deadline that haven't been expired yet
func (st userActorState) countPending() int {
	var n int
	for _, r := range st.Requests {
		if r.Status == db.V2RequestStatusPending {
			n++
		}
	}
	return n
}

// overdue returns the pending requests that are past their deadline, sorted by state
func (st userActorState) overdue(now time.Time) []string {
	var res []string
	for state, r := range st.Requests {
		if r.isOverdue(now) {
			res = append(res, state)
		}
	}

	slices.Sort(res)
	return res
}

// Request is the metadata of a request, kept in the revaulter.user actor
// The envelopes are stored in the v2_request_payloads table
type Request struct {
	Status          db.V2RequestStatus
	Operation       string
	KeyLabel        string
	Algorithm       string
	RequestorIP     string
	Note            string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ResultTokenHash string
	// Token of the long-poll that currently waits for the result, if any
	Waiter string
}

// isOverdue returns true if the request is pending but past its deadline
func (r Request) isOverdue(now time.Time) bool {
	return r.Status == db.V2RequestStatusPending && now.After(r.ExpiresAt)
}

// cleanupDue returns when the cleanup alarm must process the request
// A pending request is expired shortly after its deadline, and a finished one is removed some time later
func (r Request) cleanupDue() time.Time {
	if r.Status == db.V2RequestStatusPending {
		return r.ExpiresAt.Add(requestExpiryGrace)
	}

	return r.ExpiresAt.Add(RequestRemoveGrace)
}

// listItem returns the request as an item for the pending list
func (r Request) listItem(state string, userID string) db.V2RequestListItem {
	return db.V2RequestListItem{
		State:     state,
		Status:    string(r.Status),
		Operation: r.Operation,
		UserID:    userID,
		KeyLabel:  r.KeyLabel,
		Algorithm: r.Algorithm,
		Requestor: r.RequestorIP,
		Date:      r.CreatedAt.Unix(),
		Expiry:    r.ExpiresAt.Unix(),
		Note:      r.Note,
	}
}

// auditMetadata returns the metadata for the request's audit events
func (r Request) auditMetadata() json.RawMessage {
	return db.RequestAuditMetadata(r.Operation, r.Algorithm, r.KeyLabel, r.Note)
}

// Input and output of the revaulter.user methods

// CreateRequestInput is the input for creating a request
type CreateRequestInput struct {
	State   string
	Request Request
	// Request envelope, stored in v2_request_payloads
	EncryptedRequest string
	// Audit event to write with the request, if any
	Audit *db.AuditEventInput
}

type userCreateRes struct {
	Error userActorErrorCode
}

type userChangeReq struct {
	State string
	// Response envelope, for confirm only
	EncryptedResult string
	// Audit event to write with the change, if any
	// The actor sets the fields that describe the request
	Audit *db.AuditEventInput
}

type userChangeRes struct {
	Error   userActorErrorCode
	Request Request
}

type userStateReq struct {
	State string
	// Waiter token, for unsubscribe only
	Waiter string
}

// Subscription is the result of subscribing to a request
type Subscription struct {
	Found  bool
	Status db.V2RequestStatus
	// Token of the new waiter, set only when the request is pending
	Waiter string
}

// CollectedResult is the result of a finished request, which collecting removes
type CollectedResult struct {
	Found  bool
	Status db.V2RequestStatus
	// Response envelope, for completed requests
	EncryptedResult string
}

// requestCheck is the status of a request, for a long-poll that checks it while waiting
type requestCheck struct {
	Found  bool
	Status db.V2RequestStatus
	// Token of the long-poll that currently waits for the result, if any
	Waiter string
}

type userGetRes struct {
	Found   bool
	Request Request
}

type userListRes struct {
	Items []db.V2RequestListItem
}

// Snapshot contains the pending requests of a user, and the bell that rings when they change
type Snapshot struct {
	Bell  string
	Items []db.V2RequestListItem
}

// waiterWake is the payload of the signal that wakes a long-poll
type waiterWake struct {
	Reason string
}

// userActor is the revaulter.user actor, which holds all requests of a user
// All replicas call the same actor for a user, so they see the same requests
type userActor struct {
	userID string
	host   *Host
	log    *slog.Logger
	client actor.Client[userActorState]

	// Due time of the cleanup alarm, as set by this activation
	// It's zero when unknown, for example after the actor is activated or after setting the alarm failed, and then the next call sets the alarm again
	alarmDue time.Time
}

// newUserActor is the factory for revaulter.user actors
func (h *Host) newUserActor(actorID string, service *actor.Service) actor.Actor {
	return &userActor{
		userID: actorID,
		host:   h,
		log:    h.log.With(slog.String("actorType", actorTypeUser), slog.String("userId", actorID)),
		client: wrapActorClient(actorTypeUser, actorID, actor.NewActorClient[userActorState](actorTypeUser, actorID, service)),
	}
}

// Invoke implements actor.ActorInvoke
func (a *userActor) Invoke(ctx context.Context, method string, data actor.Envelope) (any, error) {
	switch method {
	case userMethodCreate:
		var in CreateRequestInput
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.create(ctx, in)

	case userMethodConfirm:
		var in userChangeReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.confirm(ctx, in)

	case userMethodCancel:
		var in userChangeReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.cancel(ctx, in)

	case userMethodSubscribe:
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.subscribe(ctx, in)

	case userMethodUnsubscribe:
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return nil, a.unsubscribe(ctx, in)

	case userMethodCollect:
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.collect(ctx, in)

	case userMethodSnapshot:
		return a.snapshot(ctx)

	case userMethodCheck:
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.check(ctx, in)

	case userMethodRepair:
		// Loading the state sets the cleanup alarm again, in case it's missing
		a.alarmDue = time.Time{}
		_, err := a.loadState(ctx)
		return nil, err
	}

	if testUserMethods != nil {
		res, handled, err := testUserMethods(ctx, a, method, data)
		if handled {
			return res, err
		}
	}

	return nil, fmt.Errorf("unsupported method '%s'", method)
}

// Peek implements actor.ActorPeek
// Peek calls can run concurrently, so they must not change the state
func (a *userActor) Peek(ctx context.Context, method string, data actor.Envelope) (any, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	now := time.Now()

	switch method {
	case userMethodList:
		return userListRes{
			Items: st.pendingList(a.userID, now),
		}, nil

	case userMethodGet:
		var in userStateReq
		err = decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}

		r := st.Requests[in.State]
		if r == nil {
			return userGetRes{}, nil
		}

		// Report a request past its deadline as expired, even if the cleanup alarm hasn't run yet
		res := userGetRes{
			Found:   true,
			Request: *r,
		}
		if r.isOverdue(now) {
			res.Request.Status = db.V2RequestStatusExpired
		}
		return res, nil
	}

	return nil, fmt.Errorf("unsupported method '%s'", method)
}

// Alarm implements actor.ActorAlarm
func (a *userActor) Alarm(ctx context.Context, name string, _ actor.Envelope) error {
	if name != userActorCleanupAlarm {
		a.log.WarnContext(ctx, "Ignoring unknown alarm", slog.String("alarm", name))
		return nil
	}

	// The running alarm is deleted when it completes, unless it's replaced
	a.alarmDue = time.Time{}

	err := a.cleanup(ctx)
	if err != nil {
		a.log.WarnContext(ctx, "Failed to clean up requests; will retry", slog.Any("error", err))

		// Re-arm instead of returning an error, since Francis deletes an alarm once its retries run out
		// Replacing the alarm while it runs keeps the new one
		// If this fails too, Francis retries the run, and after that the next call to the actor, or the daily repair, sets the alarm again
		return a.setCleanupAlarm(ctx, time.Now().Add(userActorCleanupRetryDelay))
	}

	return nil
}

// loadState returns a copy of the state, which can be changed and then saved
// If this activation hasn't set the cleanup alarm, for example because the actor was just activated, or because setting it failed, it sets it now
func (a *userActor) loadState(ctx context.Context) (userActorState, error) {
	st, err := a.getState(ctx)
	if err != nil {
		return userActorState{}, err
	}

	if a.alarmDue.IsZero() && !st.isEmpty() {
		err = a.setCleanupAlarm(ctx, st.nextCleanup(config.Get().SessionTimeout))
		if err != nil {
			a.log.WarnContext(ctx, "Failed to set cleanup alarm; will retry", slog.Any("error", err))
		}
	}

	return st, nil
}

// getState returns a copy of the state, which can be changed and then saved, without setting the cleanup alarm
func (a *userActor) getState(ctx context.Context) (userActorState, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return userActorState{}, fmt.Errorf("failed to load state: %w", err)
	}

	return st.clone(), nil
}

// saveState stores the state, then moves the cleanup alarm to the earliest due time
// Once the state is stored, the change is done, so it returns an error only if storing the state fails
// If setting the alarm fails, the next call sets it again
func (a *userActor) saveState(ctx context.Context, st userActorState) error {
	err := a.client.SetState(ctx, st, nil)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	err = a.setCleanupAlarm(ctx, st.nextCleanup(config.Get().SessionTimeout))
	if err != nil {
		a.log.WarnContext(ctx, "Failed to set cleanup alarm; will retry", slog.Any("error", err))
	}

	return nil
}

// setCleanupAlarm sets the cleanup alarm to the given time, unless this activation already set it there
func (a *userActor) setCleanupAlarm(ctx context.Context, due time.Time) error {
	if due.IsZero() || due.Equal(a.alarmDue) {
		return nil
	}

	err := a.client.SetAlarm(ctx, userActorCleanupAlarm, actor.AlarmProperties{
		DueTime: due,
	})
	if err != nil {
		a.alarmDue = time.Time{}
		return fmt.Errorf("failed to set cleanup alarm: %w", err)
	}

	a.alarmDue = due
	return nil
}

// deleteState removes the state and the cleanup alarm
func (a *userActor) deleteState(ctx context.Context) error {
	err := a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		return fmt.Errorf("failed to delete state: %w", err)
	}

	err = a.client.DeleteAlarm(ctx, userActorCleanupAlarm)
	if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
		return fmt.Errorf("failed to delete cleanup alarm: %w", err)
	}
	a.alarmDue = time.Time{}

	return nil
}

// rotateBell replaces the bell after a change to the pending requests, and returns the previous one, which must be rung once the state is saved
func (a *userActor) rotateBell(st *userActorState, now time.Time) (string, error) {
	bell, err := newSignalToken()
	if err != nil {
		return "", err
	}

	prev := st.Bell
	st.Bell = bell
	st.LastChange = now
	return prev, nil
}

// ringBell wakes the list streams waiting on a bell
// It must be called after the state with the new bell is saved, or the streams would keep reading a bell that has already rung
func (a *userActor) ringBell(ctx context.Context, bell string) {
	if bell == "" {
		return
	}

	err := a.host.inbox.Complete(ctx, bell, nil)
	if err != nil && !errors.Is(err, signal.ErrAlreadyCompleted) {
		// The streams will catch up when they reconnect, at the latest when the session expires
		a.log.WarnContext(ctx, "Failed to notify list streams", slog.Any("error", err))
	}
}

// wakeWaiter wakes the long-poll waiting for the result of a request
func (a *userActor) wakeWaiter(ctx context.Context, state string, waiter string, reason string) {
	if waiter == "" {
		return
	}

	err := a.host.waiters.Complete(ctx, waiterSignalID(state, waiter), waiterWake{Reason: reason})
	if err != nil && !errors.Is(err, signal.ErrAlreadyCompleted) {
		// The long-poll finds out when it checks the request again
		a.log.WarnContext(ctx, "Failed to wake long-poll", slog.String("state", state), slog.Any("error", err))
	}
}

// create stores a new request
func (a *userActor) create(ctx context.Context, in CreateRequestInput) (userCreateRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userCreateRes{}, err
	}

	// If the request already exists, this is a retry of a call that succeeded
	_, exists := st.Requests[in.State]
	if exists {
		return userCreateRes{}, nil
	}

	// Expire the requests past their deadline first, so they don't count towards the limit even if the cleanup alarm hasn't run
	now := time.Now()
	expired := st.overdue(now)
	prevBell, waiters, err := a.expire(ctx, &st, expired, now)
	if err != nil {
		return userCreateRes{}, err
	}

	if st.countPending() >= MaxPendingRequestsPerUser {
		if len(expired) > 0 {
			err = a.saveState(ctx, st)
			if err != nil {
				return userCreateRes{}, err
			}

			a.notify(ctx, waiters, prevBell)
		}

		return userCreateRes{Error: userActorErrTooManyPending}, nil
	}

	// Store the envelope and the audit event in the same transaction, before the state
	// If an earlier attempt stored them, but failed to save the state, the request is taken from the database, with its status, and the audit event isn't written again
	stored, err := db.ExecuteInTransaction(ctx, a.host.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (storedRequest, error) {
		status, created, rErr := tx.RequestPayloadStore().Insert(ctx, db.RequestPayload{
			State:            in.State,
			UserID:           a.userID,
			ExpiresAt:        in.Request.ExpiresAt,
			EncryptedRequest: in.EncryptedRequest,
		})
		if rErr != nil {
			return storedRequest{}, rErr
		}

		recorded := created && in.Audit != nil
		if recorded {
			_, rErr = tx.AuditStore().Insert(ctx, *in.Audit)
			if rErr != nil {
				return storedRequest{}, rErr
			}
		}

		return storedRequest{
			status:   status,
			recorded: recorded,
		}, nil
	})
	if err != nil {
		return userCreateRes{}, err
	}

	if stored.recorded {
		a.host.NudgeAuditStream()
	}

	req := in.Request
	req.Status = stored.status
	req.Waiter = ""
	if st.Requests == nil {
		st.Requests = map[string]*Request{}
	}
	st.Requests[in.State] = &req

	// Expiring requests already replaced the bell
	if len(expired) == 0 {
		prevBell, err = a.rotateBell(&st, now)
		if err != nil {
			return userCreateRes{}, err
		}
	}

	err = a.saveState(ctx, st)
	if err != nil {
		return userCreateRes{}, err
	}

	a.notify(ctx, waiters, prevBell)

	return userCreateRes{}, nil
}

// notify wakes the long-polls of requests that changed, then the list streams waiting on the bell
func (a *userActor) notify(ctx context.Context, waiters map[string]string, bell string) {
	for state, waiter := range waiters {
		a.wakeWaiter(ctx, state, waiter, waiterReasonDone)
	}

	a.ringBell(ctx, bell)
}

// confirm completes a pending request with the response envelope
func (a *userActor) confirm(ctx context.Context, in userChangeReq) (userChangeRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userChangeRes{}, err
	}

	now := time.Now()
	r := st.Requests[in.State]
	if r == nil || r.Status != db.V2RequestStatusPending || r.isOverdue(now) {
		return userChangeRes{Error: userActorErrNotModifiable}, nil
	}

	// Record the status, the response envelope and the audit event in the same transaction, before the state
	stored, err := a.finishStored(ctx, in.State, db.V2RequestStatusCompleted, in.EncryptedResult, in.Audit, r)
	if errors.Is(err, db.ErrRequestPayloadNotFound) {
		// The envelope is gone, so the request can't be completed
		return userChangeRes{Error: userActorErrNotModifiable}, nil
	} else if err != nil {
		return userChangeRes{}, err
	}

	return a.finishWith(ctx, st, in.State, stored.status, db.V2RequestStatusCompleted, now)
}

// cancel cancels a pending request
func (a *userActor) cancel(ctx context.Context, in userChangeReq) (userChangeRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userChangeRes{}, err
	}

	// Unlike confirm, a request past its deadline can still be canceled until it's expired
	r := st.Requests[in.State]
	if r == nil || r.Status != db.V2RequestStatusPending {
		return userChangeRes{Error: userActorErrNotModifiable}, nil
	}

	// Record the status and the audit event in the same transaction, before the state
	stored, err := a.finishStored(ctx, in.State, db.V2RequestStatusCanceled, "", in.Audit, r)
	if err != nil {
		return userChangeRes{}, err
	}

	return a.finishWith(ctx, st, in.State, stored.status, db.V2RequestStatusCanceled, time.Now())
}

// storedRequest is the outcome of recording a request's status in the main database
type storedRequest struct {
	// Status of the request in the database
	status db.V2RequestStatus
	// True if this call recorded the change, and wrote its audit event
	recorded bool
}

// finishStored moves a pending request to a final status in the main database, together with its audit event, which is optional
// If the request is finished there already, for example by an earlier attempt that failed to save the state, it writes nothing and returns the stored status
// A request with no row can't be completed, and it returns ErrRequestPayloadNotFound for that, but it can still be canceled or expired
func (a *userActor) finishStored(ctx context.Context, state string, status db.V2RequestStatus, encryptedResult string, audit *db.AuditEventInput, r *Request) (storedRequest, error) {
	stored, err := db.ExecuteInTransaction(ctx, a.host.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (storedRequest, error) {
		current, applied, rErr := tx.RequestPayloadStore().Finish(ctx, state, a.userID, status, encryptedResult)
		if errors.Is(rErr, db.ErrRequestPayloadNotFound) && status != db.V2RequestStatusCompleted {
			current, applied, rErr = status, true, nil
		}
		if rErr != nil {
			return storedRequest{}, rErr
		}

		recorded := applied && audit != nil
		if recorded {
			_, rErr = tx.AuditStore().Insert(ctx, a.requestAuditEvent(*audit, state, r))
			if rErr != nil {
				return storedRequest{}, fmt.Errorf("failed to write audit event: %w", rErr)
			}
		}

		return storedRequest{
			status:   current,
			recorded: recorded,
		}, nil
	})
	if err != nil {
		return storedRequest{}, err
	}

	if stored.recorded {
		a.host.NudgeAuditStream()
	}

	return stored, nil
}

// finishWith moves a pending request to the status stored in the main database, then reports whether that's the status the caller asked for
// When the stored status is a different one, an earlier call finished the request differently, and the caller gets ErrRequestNotModifiable
func (a *userActor) finishWith(ctx context.Context, st userActorState, state string, stored db.V2RequestStatus, wanted db.V2RequestStatus, now time.Time) (userChangeRes, error) {
	res, err := a.finish(ctx, &st, state, stored, now)
	if err != nil {
		return userChangeRes{}, err
	}

	if stored != wanted {
		return userChangeRes{Error: userActorErrNotModifiable}, nil
	}

	return res, nil
}

// syncRequest moves a request that's pending in the state to the final status stored in the main database, if it has one
// A change is recorded in the database first, so the request can be finished there while still pending here, for example if saving the state failed
func (a *userActor) syncRequest(ctx context.Context, st *userActorState, state string) error {
	r := st.Requests[state]
	if r == nil || r.Status != db.V2RequestStatusPending {
		return nil
	}

	p, err := a.host.db.RequestPayloadStore().Get(ctx, state, a.userID)
	if err != nil {
		return err
	}
	if p == nil || !p.Status.IsTerminal() {
		return nil
	}

	_, err = a.finish(ctx, st, state, p.Status, time.Now())
	return err
}

// finish moves a pending request to a final state, then wakes its long-poll and the list streams
func (a *userActor) finish(ctx context.Context, st *userActorState, state string, status db.V2RequestStatus, now time.Time) (userChangeRes, error) {
	r := st.Requests[state]
	r.Status = status
	waiter := r.Waiter
	r.Waiter = ""

	prevBell, err := a.rotateBell(st, now)
	if err != nil {
		return userChangeRes{}, err
	}

	err = a.saveState(ctx, *st)
	if err != nil {
		return userChangeRes{}, err
	}

	a.wakeWaiter(ctx, state, waiter, waiterReasonDone)
	a.ringBell(ctx, prevBell)

	return userChangeRes{Request: *r}, nil
}

// requestAuditEvent completes an audit event with the fields that describe a request
func (a *userActor) requestAuditEvent(in db.AuditEventInput, state string, r *Request) db.AuditEventInput {
	in.TargetUserID = &a.userID
	in.RequestState = &state
	in.Metadata = r.auditMetadata()
	return in
}

// expire moves the given pending requests to the expired state, recording each expiry in the audit log, or to the final status stored in the main database if they have one
// The caller must save the state, then ring the returned bell and wake the returned waiters
func (a *userActor) expire(ctx context.Context, st *userActorState, states []string, now time.Time) (prevBell string, waiters map[string]string, err error) {
	if len(states) == 0 {
		return "", nil, nil
	}

	// Record the expiry of each request and its audit event in the same transaction, before the state
	// A request that's finished in the database already, for example by a confirmation that failed to save the state, keeps that status, and gets no expiry event
	statuses, err := db.ExecuteInTransaction(ctx, a.host.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (map[string]db.V2RequestStatus, error) {
		res := make(map[string]db.V2RequestStatus, len(states))
		events := make([]db.AuditEventInput, 0, len(states))
		for i, state := range states {
			current, applied, rErr := tx.RequestPayloadStore().Finish(ctx, state, a.userID, db.V2RequestStatusExpired, "")
			if errors.Is(rErr, db.ErrRequestPayloadNotFound) {
				current, applied, rErr = db.V2RequestStatusExpired, true, nil
			}
			if rErr != nil {
				return nil, rErr
			}
			res[state] = current

			if !applied {
				continue
			}

			// Expiry is performed by the system, and the request's owner is both the actor and the target
			events = append(events, db.AuditEventInput{
				EventType:    db.AuditRequestExpire,
				Outcome:      db.AuditOutcomeSuccess,
				AuthMethod:   db.AuditAuthMethodSystem,
				ActorUserID:  &a.userID,
				TargetUserID: &a.userID,
				RequestState: &states[i],
				Metadata:     st.Requests[state].auditMetadata(),
			})
		}

		if len(events) > 0 {
			rErr := tx.AuditStore().InsertMany(ctx, events)
			if rErr != nil {
				return nil, rErr
			}
		}

		return res, nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to record request expiry: %w", err)
	}

	a.host.NudgeAuditStream()

	waiters = make(map[string]string, len(states))
	for _, state := range states {
		r := st.Requests[state]
		r.Status = statuses[state]
		if r.Waiter != "" {
			waiters[state] = r.Waiter
			r.Waiter = ""
		}
	}

	prevBell, err = a.rotateBell(st, now)
	if err != nil {
		return "", nil, err
	}

	return prevBell, waiters, nil
}

// expireOne expires a single request if it's past its deadline, saving the state and notifying waiters
func (a *userActor) expireOne(ctx context.Context, st *userActorState, state string, now time.Time) error {
	r := st.Requests[state]
	if r == nil || !r.isOverdue(now) {
		return nil
	}

	prevBell, waiters, err := a.expire(ctx, st, []string{state}, now)
	if err != nil {
		return err
	}

	err = a.saveState(ctx, *st)
	if err != nil {
		return err
	}

	for s, w := range waiters {
		a.wakeWaiter(ctx, s, w, waiterReasonDone)
	}
	a.ringBell(ctx, prevBell)

	return nil
}

// subscribe registers a new long-poll for the result of a request, evicting the previous one
// Reading the status and registering the waiter in the same turn means that any later change wakes the new waiter
func (a *userActor) subscribe(ctx context.Context, in userStateReq) (Subscription, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return Subscription{}, err
	}

	r := st.Requests[in.State]
	if r == nil {
		return Subscription{}, nil
	}

	// If the request is finished in the main database, or past its deadline, finish it now so the caller gets a final answer right away
	err = a.syncRequest(ctx, &st, in.State)
	if err != nil {
		return Subscription{}, err
	}

	err = a.expireOne(ctx, &st, in.State, time.Now())
	if err != nil {
		return Subscription{}, err
	}

	if r.Status != db.V2RequestStatusPending {
		return Subscription{
			Found:  true,
			Status: r.Status,
		}, nil
	}

	waiter, err := newSignalToken()
	if err != nil {
		return Subscription{}, err
	}

	evicted := r.Waiter
	r.Waiter = waiter
	err = a.saveState(ctx, st)
	if err != nil {
		return Subscription{}, err
	}

	a.wakeWaiter(ctx, in.State, evicted, waiterReasonEvicted)

	return Subscription{
		Found:  true,
		Status: r.Status,
		Waiter: waiter,
	}, nil
}

// check returns the status of a request, and the waiter of its current long-poll
// Like subscribe, it finishes a request that's finished in the main database or past its deadline, but it doesn't register a waiter
func (a *userActor) check(ctx context.Context, in userStateReq) (requestCheck, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return requestCheck{}, err
	}

	r := st.Requests[in.State]
	if r == nil {
		return requestCheck{}, nil
	}

	err = a.syncRequest(ctx, &st, in.State)
	if err != nil {
		return requestCheck{}, err
	}
	err = a.expireOne(ctx, &st, in.State, time.Now())
	if err != nil {
		return requestCheck{}, err
	}

	return requestCheck{
		Found:  true,
		Status: r.Status,
		Waiter: r.Waiter,
	}, nil
}

// unsubscribe removes a long-poll's waiter, if it's still the current one
func (a *userActor) unsubscribe(ctx context.Context, in userStateReq) error {
	st, err := a.loadState(ctx)
	if err != nil {
		return err
	}

	r := st.Requests[in.State]
	if r == nil || in.Waiter == "" || r.Waiter != in.Waiter {
		return nil
	}

	r.Waiter = ""

	return a.saveState(ctx, st)
}

// collect returns the result of a finished request and removes it
// This runs in a single turn, so only one caller can collect a result
func (a *userActor) collect(ctx context.Context, in userStateReq) (CollectedResult, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return CollectedResult{}, err
	}

	r := st.Requests[in.State]
	if r == nil {
		return CollectedResult{}, nil
	}

	err = a.syncRequest(ctx, &st, in.State)
	if err != nil {
		return CollectedResult{}, err
	}
	err = a.expireOne(ctx, &st, in.State, time.Now())
	if err != nil {
		return CollectedResult{}, err
	}

	if r.Status == db.V2RequestStatusPending {
		return CollectedResult{
			Found:  true,
			Status: r.Status,
		}, nil
	}

	res := CollectedResult{
		Found:  true,
		Status: r.Status,
	}
	if r.Status == db.V2RequestStatusCompleted {
		payload, err := a.host.db.RequestPayloadStore().Get(ctx, in.State, a.userID)
		if err != nil {
			return CollectedResult{}, err
		}
		if payload == nil || payload.EncryptedResult == "" {
			// The envelope is gone, so there's no result to return
			return CollectedResult{}, nil
		}
		res.EncryptedResult = payload.EncryptedResult
	}

	// Remove the request from the state first, so the result can't be collected twice
	delete(st.Requests, in.State)
	err = a.saveState(ctx, st)
	if err != nil {
		return CollectedResult{}, err
	}

	// If this fails, the row is removed by the periodic prune
	err = a.host.db.RequestPayloadStore().Delete(ctx, a.userID, in.State)
	if err != nil {
		a.log.WarnContext(ctx, "Failed to delete request payload", slog.String("state", in.State), slog.Any("error", err))
	}

	return res, nil
}

// snapshot returns the bell and the pending requests, read in the same turn so no change can happen in between
func (a *userActor) snapshot(ctx context.Context) (Snapshot, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	now := time.Now()

	// Create a bell for the stream to wait on
	if st.Bell == "" {
		_, err = a.rotateBell(&st, now)
		if err != nil {
			return Snapshot{}, err
		}

		err = a.saveState(ctx, st)
		if err != nil {
			return Snapshot{}, err
		}
	}

	return Snapshot{
		Bell:  st.Bell,
		Items: st.pendingList(a.userID, now),
	}, nil
}

// cleanup expires the pending requests past their deadline, and removes the finished ones that have been kept long enough
func (a *userActor) cleanup(ctx context.Context) error {
	st, err := a.getState(ctx)
	if err != nil {
		return err
	}

	if st.isEmpty() {
		return nil
	}

	now := time.Now()

	// Expire pending requests past their deadline
	toExpire := st.overdue(now)
	prevBell, waiters, err := a.expire(ctx, &st, toExpire, now)
	if err != nil {
		return err
	}

	// Remove finished requests, including any just expired that are past the removal grace period, for example after downtime
	var toRemove []string
	for state, r := range st.Requests {
		if r.Status.IsTerminal() && !now.Before(r.ExpiresAt.Add(RequestRemoveGrace)) {
			toRemove = append(toRemove, state)
		}
	}

	if len(toRemove) > 0 {
		err = a.host.db.RequestPayloadStore().Delete(ctx, a.userID, toRemove...)
		if err != nil {
			return err
		}

		for _, state := range toRemove {
			delete(st.Requests, state)
		}
	}

	// With no requests left, the bell is kept for one session timeout after the last change, then the state is deleted
	if len(st.Requests) == 0 && !now.Before(st.LastChange.Add(config.Get().SessionTimeout)) {
		err = a.deleteState(ctx)
		if err != nil {
			return err
		}

		// Ring the current bell after the state is deleted, so open list streams take a fresh one
		for state, waiter := range waiters {
			a.wakeWaiter(ctx, state, waiter, waiterReasonDone)
		}

		a.ringBell(ctx, prevBell)
		a.ringBell(ctx, st.Bell)
		return nil
	}

	if len(toExpire) == 0 && len(toRemove) == 0 {
		// Nothing changed, but the alarm must still be set for the next due time
		return a.setCleanupAlarm(ctx, st.nextCleanup(config.Get().SessionTimeout))
	}

	err = a.saveState(ctx, st)
	if err != nil {
		return err
	}

	a.notify(ctx, waiters, prevBell)

	// The alarm that runs now is deleted when it completes, so a failure to set the next one is an error, which makes the caller retry
	if a.alarmDue.IsZero() {
		return errors.New("failed to set the next cleanup alarm")
	}

	return nil
}

// waiterSignalID returns the ID of the signal that wakes a long-poll
func waiterSignalID(state string, waiter string) string {
	return state + ":" + waiter
}

// newSignalToken returns a random token for a bell or a waiter
func newSignalToken() (string, error) {
	return utils.RandomString(24)
}
