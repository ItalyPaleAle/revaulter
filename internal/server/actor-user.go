package server

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

	// signalSetWaiters wakes the long-polls waiting for the result of a request
	signalSetWaiters = "revaulter-waiters"
	// signalSetInbox wakes the list streams of a user when the pending requests change
	signalSetInbox = "revaulter-inbox"

	// maxPendingRequestsPerUser caps the number of requests a user can have pending at once
	maxPendingRequestsPerUser = 50
	// requestExpiryGrace is added to a request's deadline when scheduling its expiry, so the deadline has passed when the alarm fires
	requestExpiryGrace = 5 * time.Second
	// requestRemoveGrace is how long a finished request is kept after its deadline, so the caller can still collect its result
	requestRemoveGrace = 10 * time.Minute
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

	// Methods used by the e2e tests only
	userMethodTestReset  = "test-reset"
	userMethodTestExpire = "test-expire"
)

// Reasons sent to the long-poll waiting for the result of a request
const (
	// The request reached a final state
	waiterReasonDone = "done"
	// A newer long-poll for the same request took over
	waiterReasonEvicted = "evicted"
)

// enableUserActorTestMethods allows invoking the methods used by the e2e tests
// It's set in e2e_routes_testbuild.go
var enableUserActorTestMethods = false

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
	Requests map[string]*userRequest
	// Signal ID that list streams wait on, replaced on every change to the pending requests
	Bell string
	// Time of the last change to the pending requests
	// When there are no requests left, the bell is kept for one session timeout after this
	LastChange time.Time
}

// clone returns a deep copy of the state, so changes can be discarded if they fail to be saved
func (st userActorState) clone() userActorState {
	res := st
	res.Requests = make(map[string]*userRequest, len(st.Requests))
	for k, v := range st.Requests {
		r := *v
		res.Requests[k] = &r
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

// userRequest is the metadata of a request, kept in the revaulter.user actor
// The envelopes are stored in the v2_request_payloads table
type userRequest struct {
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
func (r userRequest) isOverdue(now time.Time) bool {
	return r.Status == db.V2RequestStatusPending && now.After(r.ExpiresAt)
}

// cleanupDue returns when the cleanup alarm must process the request
// A pending request is expired shortly after its deadline, and a finished one is removed some time later
func (r userRequest) cleanupDue() time.Time {
	if r.Status == db.V2RequestStatusPending {
		return r.ExpiresAt.Add(requestExpiryGrace)
	}
	return r.ExpiresAt.Add(requestRemoveGrace)
}

// listItem returns the request as an item for the pending list
func (r userRequest) listItem(state string, userID string) db.V2RequestListItem {
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
func (r userRequest) auditMetadata() json.RawMessage {
	return db.RequestAuditMetadata(r.Operation, r.Algorithm, r.KeyLabel, r.Note)
}

// Input and output of the revaulter.user methods

type userCreateReq struct {
	State   string
	Request userRequest
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
	Request userRequest
}

type userStateReq struct {
	State string
	// Waiter token, for unsubscribe only
	Waiter string
}

type userSubscribeRes struct {
	Found  bool
	Status db.V2RequestStatus
	// Token of the new waiter, set only when the request is pending
	Waiter string
}

type userCollectRes struct {
	Found  bool
	Status db.V2RequestStatus
	// Response envelope, for completed requests
	EncryptedResult string
}

type userGetRes struct {
	Found   bool
	Request userRequest
}

type userListRes struct {
	Items []db.V2RequestListItem
}

type userSnapshotRes struct {
	Bell  string
	Items []db.V2RequestListItem
}

// waiterWake is the payload of the signal that wakes a long-poll
type waiterWake struct {
	Reason string
}

// userActor is the revaulter.user actor, which holds all requests of a user
// It replaces the requests table, the expiry timers, and the in-memory notifications, so every replica sees the same requests
type userActor struct {
	userID string
	srv    *Server
	log    *slog.Logger
	client actor.Client[userActorState]

	// Due time of the cleanup alarm, as set by this activation
	// It's zero when unknown, in which case the alarm is always set
	alarmDue time.Time
}

// newUserActorFactory returns the factory for revaulter.user actors
func (s *Server) newUserActorFactory(log *slog.Logger) actor.Factory {
	return func(actorID string, service *actor.Service) actor.Actor {
		return &userActor{
			userID: actorID,
			srv:    s,
			log:    log.With(slog.String("actorType", actorTypeUser), slog.String("userId", actorID)),
			client: actor.NewActorClient[userActorState](actorTypeUser, actorID, service),
		}
	}
}

// Invoke implements actor.ActorInvoke
func (a *userActor) Invoke(ctx context.Context, method string, data actor.Envelope) (any, error) {
	switch method {
	case userMethodCreate:
		var in userCreateReq
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
	case userMethodTestReset:
		if !enableUserActorTestMethods {
			break
		}
		return nil, a.testReset(ctx)
	case userMethodTestExpire:
		if !enableUserActorTestMethods {
			break
		}
		var in userStateReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return nil, a.testExpire(ctx, in)
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
		return a.setCleanupAlarm(ctx, time.Now().Add(userActorCleanupRetryDelay))
	}

	return nil
}

// loadState returns a copy of the state, which can be changed and then saved
func (a *userActor) loadState(ctx context.Context) (userActorState, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return userActorState{}, fmt.Errorf("failed to load state: %w", err)
	}

	return st.clone(), nil
}

// saveState stores the state, then moves the cleanup alarm to the earliest due time
func (a *userActor) saveState(ctx context.Context, st userActorState) error {
	err := a.client.SetState(ctx, st, nil)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return a.setCleanupAlarm(ctx, st.nextCleanup(config.Get().SessionTimeout))
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

	err := a.srv.inbox.Complete(ctx, bell, nil)
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

	err := a.srv.waiters.Complete(ctx, waiterSignalID(state, waiter), waiterWake{Reason: reason})
	if err != nil && !errors.Is(err, signal.ErrAlreadyCompleted) {
		// The caller will see the change the next time it polls
		a.log.WarnContext(ctx, "Failed to wake long-poll", slog.String("state", state), slog.Any("error", err))
	}
}

// create stores a new request
func (a *userActor) create(ctx context.Context, in userCreateReq) (userCreateRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userCreateRes{}, err
	}

	// If the request already exists, this is a retry of a call that succeeded
	_, exists := st.Requests[in.State]
	if exists {
		return userCreateRes{}, nil
	}

	if st.countPending() >= maxPendingRequestsPerUser {
		return userCreateRes{Error: userActorErrTooManyPending}, nil
	}

	// Store the envelope and the audit event first
	// If saving the state fails afterwards, the audit log has an event for a request that doesn't exist, rather than a request that's missing from the audit log
	_, err = db.ExecuteInTransaction(ctx, a.srv.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.RequestPayloadStore().Insert(ctx, db.RequestPayload{
			State:            in.State,
			UserID:           a.userID,
			ExpiresAt:        in.Request.ExpiresAt,
			EncryptedRequest: in.EncryptedRequest,
		})
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
	if err != nil {
		return userCreateRes{}, err
	}
	if in.Audit != nil {
		a.srv.nudgeAuditStream()
	}

	now := time.Now()
	req := in.Request
	req.Status = db.V2RequestStatusPending
	req.Waiter = ""
	if st.Requests == nil {
		st.Requests = map[string]*userRequest{}
	}
	st.Requests[in.State] = &req

	prevBell, err := a.rotateBell(&st, now)
	if err != nil {
		return userCreateRes{}, err
	}

	err = a.saveState(ctx, st)
	if err != nil {
		return userCreateRes{}, err
	}

	a.ringBell(ctx, prevBell)

	return userCreateRes{}, nil
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

	// Store the response envelope and the audit event first
	_, err = db.ExecuteInTransaction(ctx, a.srv.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		rErr := tx.RequestPayloadStore().SetResult(ctx, in.State, a.userID, in.EncryptedResult)
		if rErr != nil {
			return struct{}{}, rErr
		}

		if in.Audit != nil {
			_, rErr = tx.AuditStore().Insert(ctx, a.requestAuditEvent(*in.Audit, in.State, r))
			if rErr != nil {
				return struct{}{}, rErr
			}
		}

		return struct{}{}, nil
	})
	if errors.Is(err, db.ErrRequestPayloadNotFound) {
		// The envelope is gone, so the request can't be completed
		return userChangeRes{Error: userActorErrNotModifiable}, nil
	} else if err != nil {
		return userChangeRes{}, err
	}
	if in.Audit != nil {
		a.srv.nudgeAuditStream()
	}

	return a.finish(ctx, st, in.State, db.V2RequestStatusCompleted, now)
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

	if in.Audit != nil {
		_, err = a.srv.db.AuditStore().Insert(ctx, a.requestAuditEvent(*in.Audit, in.State, r))
		if err != nil {
			return userChangeRes{}, fmt.Errorf("failed to write audit event: %w", err)
		}
		a.srv.nudgeAuditStream()
	}

	return a.finish(ctx, st, in.State, db.V2RequestStatusCanceled, time.Now())
}

// finish moves a pending request to a final state, then wakes its long-poll and the list streams
func (a *userActor) finish(ctx context.Context, st userActorState, state string, status db.V2RequestStatus, now time.Time) (userChangeRes, error) {
	r := st.Requests[state]
	r.Status = status
	waiter := r.Waiter
	r.Waiter = ""

	prevBell, err := a.rotateBell(&st, now)
	if err != nil {
		return userChangeRes{}, err
	}

	err = a.saveState(ctx, st)
	if err != nil {
		return userChangeRes{}, err
	}

	a.wakeWaiter(ctx, state, waiter, waiterReasonDone)
	a.ringBell(ctx, prevBell)

	return userChangeRes{Request: *r}, nil
}

// requestAuditEvent completes an audit event with the fields that describe a request
func (a *userActor) requestAuditEvent(in db.AuditEventInput, state string, r *userRequest) db.AuditEventInput {
	in.TargetUserID = &a.userID
	in.RequestState = &state
	in.Metadata = r.auditMetadata()
	return in
}

// expire moves the given pending requests to the expired state, recording each expiry in the audit log
// The caller must save the state, then ring the returned bell and wake the returned waiters
func (a *userActor) expire(ctx context.Context, st *userActorState, states []string, now time.Time) (prevBell string, waiters map[string]string, err error) {
	if len(states) == 0 {
		return "", nil, nil
	}

	// Expiry is performed by the system, and the request's owner is both the actor and the target
	events := make([]db.AuditEventInput, len(states))
	for i, state := range states {
		events[i] = db.AuditEventInput{
			EventType:    db.AuditRequestExpire,
			Outcome:      db.AuditOutcomeSuccess,
			AuthMethod:   db.AuditAuthMethodSystem,
			ActorUserID:  &a.userID,
			TargetUserID: &a.userID,
			RequestState: &states[i],
			Metadata:     st.Requests[state].auditMetadata(),
		}
	}

	// Write the audit events before changing the state
	_, err = db.ExecuteInTransaction(ctx, a.srv.db, userActorDBTimeout, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		return struct{}{}, tx.AuditStore().InsertMany(ctx, events)
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to write audit events for request expiry: %w", err)
	}
	a.srv.nudgeAuditStream()

	waiters = make(map[string]string, len(states))
	for _, state := range states {
		r := st.Requests[state]
		r.Status = db.V2RequestStatusExpired
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
func (a *userActor) subscribe(ctx context.Context, in userStateReq) (userSubscribeRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userSubscribeRes{}, err
	}

	r := st.Requests[in.State]
	if r == nil {
		return userSubscribeRes{}, nil
	}

	// If the request is past its deadline, expire it now so the caller gets a final answer right away
	err = a.expireOne(ctx, &st, in.State, time.Now())
	if err != nil {
		return userSubscribeRes{}, err
	}

	if r.Status != db.V2RequestStatusPending {
		return userSubscribeRes{
			Found:  true,
			Status: r.Status,
		}, nil
	}

	waiter, err := newSignalToken()
	if err != nil {
		return userSubscribeRes{}, err
	}

	evicted := r.Waiter
	r.Waiter = waiter
	err = a.saveState(ctx, st)
	if err != nil {
		return userSubscribeRes{}, err
	}

	a.wakeWaiter(ctx, in.State, evicted, waiterReasonEvicted)

	return userSubscribeRes{
		Found:  true,
		Status: r.Status,
		Waiter: waiter,
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
func (a *userActor) collect(ctx context.Context, in userStateReq) (userCollectRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userCollectRes{}, err
	}

	r := st.Requests[in.State]
	if r == nil {
		return userCollectRes{}, nil
	}

	err = a.expireOne(ctx, &st, in.State, time.Now())
	if err != nil {
		return userCollectRes{}, err
	}

	if r.Status == db.V2RequestStatusPending {
		return userCollectRes{
			Found:  true,
			Status: r.Status,
		}, nil
	}

	res := userCollectRes{
		Found:  true,
		Status: r.Status,
	}
	if r.Status == db.V2RequestStatusCompleted {
		payload, err := a.srv.db.RequestPayloadStore().Get(ctx, in.State, a.userID)
		if err != nil {
			return userCollectRes{}, err
		}
		if payload == nil || payload.EncryptedResult == "" {
			// The envelope is gone, so there's no result to return
			return userCollectRes{}, nil
		}
		res.EncryptedResult = payload.EncryptedResult
	}

	// Remove the request from the state first, so the result can't be collected twice
	delete(st.Requests, in.State)
	err = a.saveState(ctx, st)
	if err != nil {
		return userCollectRes{}, err
	}

	// If this fails, the row is removed by the periodic prune
	err = a.srv.db.RequestPayloadStore().Delete(ctx, a.userID, in.State)
	if err != nil {
		a.log.WarnContext(ctx, "Failed to delete request payload", slog.String("state", in.State), slog.Any("error", err))
	}

	return res, nil
}

// snapshot returns the bell and the pending requests, read in the same turn so no change can slip in between
func (a *userActor) snapshot(ctx context.Context) (userSnapshotRes, error) {
	st, err := a.loadState(ctx)
	if err != nil {
		return userSnapshotRes{}, err
	}

	now := time.Now()

	// Create a bell for the stream to wait on
	if st.Bell == "" {
		_, err = a.rotateBell(&st, now)
		if err != nil {
			return userSnapshotRes{}, err
		}

		err = a.saveState(ctx, st)
		if err != nil {
			return userSnapshotRes{}, err
		}
	}

	return userSnapshotRes{
		Bell:  st.Bell,
		Items: st.pendingList(a.userID, now),
	}, nil
}

// cleanup expires the pending requests past their deadline, and removes the finished ones that have been kept long enough
func (a *userActor) cleanup(ctx context.Context) error {
	st, err := a.loadState(ctx)
	if err != nil {
		return err
	}

	if st.isEmpty() {
		return nil
	}

	now := time.Now()

	// Expire pending requests past their deadline
	var toExpire []string
	for state, r := range st.Requests {
		if r.isOverdue(now) {
			toExpire = append(toExpire, state)
		}
	}
	slices.Sort(toExpire)
	prevBell, waiters, err := a.expire(ctx, &st, toExpire, now)
	if err != nil {
		return err
	}

	// Remove finished requests, including any just expired that are past the removal grace period, for example after downtime
	var toRemove []string
	for state, r := range st.Requests {
		if r.Status.IsTerminal() && !now.Before(r.ExpiresAt.Add(requestRemoveGrace)) {
			toRemove = append(toRemove, state)
		}
	}
	if len(toRemove) > 0 {
		err = a.srv.db.RequestPayloadStore().Delete(ctx, a.userID, toRemove...)
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

	for state, waiter := range waiters {
		a.wakeWaiter(ctx, state, waiter, waiterReasonDone)
	}
	a.ringBell(ctx, prevBell)

	return nil
}

// testReset removes all requests of the user
// It's used by the e2e tests only
func (a *userActor) testReset(ctx context.Context) error {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	err = a.deleteState(ctx)
	if err != nil {
		return err
	}

	for state, r := range st.Requests {
		a.wakeWaiter(ctx, state, r.Waiter, waiterReasonDone)
	}
	a.ringBell(ctx, st.Bell)

	return nil
}

// testExpire moves a pending request past its deadline, and expires it
// It's used by the e2e tests only
func (a *userActor) testExpire(ctx context.Context, in userStateReq) error {
	st, err := a.loadState(ctx)
	if err != nil {
		return err
	}

	r := st.Requests[in.State]
	if r == nil || r.Status != db.V2RequestStatusPending {
		return nil
	}

	now := time.Now()
	r.ExpiresAt = now.Add(-time.Second)
	return a.expireOne(ctx, &st, in.State, now)
}

// waiterSignalID returns the ID of the signal that wakes a long-poll
func waiterSignalID(state string, waiter string) string {
	return state + ":" + waiter
}

// newSignalToken returns a random token for a bell or a waiter
func newSignalToken() (string, error) {
	return utils.RandomString(24)
}

// decodeActorEnvelope decodes the data passed to an actor method
func decodeActorEnvelope(data actor.Envelope, into any) error {
	if data == nil {
		return errors.New("missing input data")
	}

	err := data.Decode(into)
	if err != nil {
		return fmt.Errorf("failed to decode input data: %w", err)
	}

	return nil
}
