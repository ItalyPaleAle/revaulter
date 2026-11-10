package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/italypaleale/francis/actor"
)

const (
	// actorTypeChallenge is the actor type that holds WebAuthn challenges for sign-ins and for adding passkeys
	actorTypeChallenge = "revaulter.challenge"
	// challengeActorCleanupAlarm is the name of the alarm that deletes a challenge once it expires
	challengeActorCleanupAlarm = "cleanup"
	// challengeActorIdleTimeout is how long a challenge actor stays in memory after its last call, as challenges are short-lived
	challengeActorIdleTimeout = time.Minute
	// maxChallengeIDLength is the maximum length of a challenge ID sent by a client
	maxChallengeIDLength = 64
)

// Methods of the revaulter.challenge actor
const (
	challengeMethodBegin   = "begin"
	challengeMethodConsume = "consume"
	challengeMethodPending = "pending"
)

// ChallengeKind is the kind of WebAuthn ceremony a challenge is for
type ChallengeKind string

const (
	// ChallengeKindLogin is a sign-in
	// Each sign-in has its own challenge
	ChallengeKindLogin ChallengeKind = "login"
	// ChallengeKindAddCredential is the registration of a new passkey for a signed-in user
	// A user has at most one pending, so beginning a new one replaces the previous one
	// #nosec G101 -- This is the name of a ceremony, not a credential
	ChallengeKindAddCredential ChallengeKind = "add-credential"
)

// ErrInvalidChallenge is returned when a challenge doesn't exist, has expired, was already used, or belongs to another user or ceremony
var ErrInvalidChallenge = errors.New("challenge is invalid or expired")

// challengeActorState is the state of a revaulter.challenge actor
type challengeActorState struct {
	Kind ChallengeKind
	// ID of the challenge, as sent to the client
	ChallengeID string
	// User the challenge is bound to, for add-credential challenges
	UserID    string
	ExpiresAt time.Time
	// Payload for the handler that consumes the challenge, which includes the WebAuthn session data, encoded as JSON
	Payload []byte
}

type challengeBeginReq struct {
	State challengeActorState
}

type challengeConsumeReq struct {
	Kind        ChallengeKind
	ChallengeID string
	UserID      string
}

type challengeConsumeRes struct {
	Found   bool
	Payload []byte
}

type challengePendingRes struct {
	Pending bool
}

// testChallengeMethods handles the methods of the revaulter.challenge actor used by the e2e tests, returning false when the method isn't one of them
// This is only set in e2e builds
var testChallengeMethods func(ctx context.Context, a *challengeActor, method string, data actor.Envelope) (res any, handled bool, err error)

// challengeActor is the revaulter.challenge actor, which holds one WebAuthn challenge until it's used or it expires
type challengeActor struct {
	host   *Host
	log    *slog.Logger
	client actor.Client[challengeActorState]
}

// newChallengeActor is the factory for revaulter.challenge actors
func (h *Host) newChallengeActor(actorID string, service *actor.Service) actor.Actor {
	return &challengeActor{
		host: h,
		log: h.log.With(
			slog.String("actorType", actorTypeChallenge),
			slog.String("actorId", actorID),
		),
		client: actor.NewActorClient[challengeActorState](actorTypeChallenge, actorID, service),
	}
}

// Invoke implements actor.ActorInvoke
func (a *challengeActor) Invoke(ctx context.Context, method string, data actor.Envelope) (any, error) {
	switch method {
	case challengeMethodBegin:
		var in challengeBeginReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return nil, a.begin(ctx, in)

	case challengeMethodConsume:
		var in challengeConsumeReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.consume(ctx, in)

	}

	if testChallengeMethods != nil {
		res, handled, err := testChallengeMethods(ctx, a, method, data)
		if handled {
			return res, err
		}
	}

	return nil, fmt.Errorf("unsupported method '%s'", method)
}

// Peek implements actor.ActorPeek
func (a *challengeActor) Peek(ctx context.Context, method string, _ actor.Envelope) (any, error) {
	if method != challengeMethodPending {
		return nil, fmt.Errorf("unsupported method '%s'", method)
	}

	st, err := a.client.GetState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	return challengePendingRes{
		Pending: st.ChallengeID != "" && !time.Now().After(st.ExpiresAt),
	}, nil
}

// Alarm implements actor.ActorAlarm
func (a *challengeActor) Alarm(ctx context.Context, name string, _ actor.Envelope) error {
	if name != challengeActorCleanupAlarm {
		a.log.WarnContext(ctx, "Ignoring unknown alarm", slog.String("alarm", name))
		return nil
	}

	// A challenge replaced after this alarm was set has a later expiry
	st, err := a.client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	if st.ChallengeID != "" && time.Now().Before(st.ExpiresAt) {
		return a.client.SetAlarm(ctx, challengeActorCleanupAlarm, actor.AlarmProperties{DueTime: st.ExpiresAt})
	}

	err = a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		// Re-arm instead of returning an error, since Francis deletes an alarm once its retries run out
		a.log.WarnContext(ctx, "Failed to delete expired challenge; will retry", slog.Any("error", err))
		return a.client.SetAlarm(ctx, challengeActorCleanupAlarm, actor.AlarmProperties{DueTime: time.Now().Add(time.Minute)})
	}

	return nil
}

// begin stores a challenge, replacing any previous one, and sets the cleanup alarm at its expiry
func (a *challengeActor) begin(ctx context.Context, in challengeBeginReq) error {
	err := a.client.SetState(ctx, in.State, nil)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	err = a.client.SetAlarm(ctx, challengeActorCleanupAlarm, actor.AlarmProperties{DueTime: in.State.ExpiresAt})
	if err != nil {
		return fmt.Errorf("failed to set cleanup alarm: %w", err)
	}

	return nil
}

// consume returns the challenge's payload and deletes it, so it can be used once only
// It returns no payload if the challenge doesn't match the kind, ID and user, or has expired
func (a *challengeActor) consume(ctx context.Context, in challengeConsumeReq) (challengeConsumeRes, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return challengeConsumeRes{}, fmt.Errorf("failed to load state: %w", err)
	}

	if st.ChallengeID == "" || st.Kind != in.Kind || st.ChallengeID != in.ChallengeID || st.UserID != in.UserID || time.Now().After(st.ExpiresAt) {
		return challengeConsumeRes{}, nil
	}

	err = a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		return challengeConsumeRes{}, fmt.Errorf("failed to delete state: %w", err)
	}

	// The challenge is gone already, so a failure here only leaves an alarm that finds nothing to delete
	err = a.client.DeleteAlarm(ctx, challengeActorCleanupAlarm)
	if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
		a.log.WarnContext(ctx, "Failed to delete cleanup alarm", slog.Any("error", err))
	}

	return challengeConsumeRes{
		Found:   true,
		Payload: st.Payload,
	}, nil
}

// challengeActorID returns the ID of the actor that holds a challenge
// Sign-in challenges are keyed by their own ID, and add-credential challenges by the user they're bound to
func challengeActorID(kind ChallengeKind, challengeID string, userID string) (string, error) {
	switch kind {
	case ChallengeKindLogin:
		if challengeID == "" || len(challengeID) > maxChallengeIDLength || strings.ContainsRune(challengeID, '/') {
			return "", ErrInvalidChallenge
		}
		return string(kind) + ":" + challengeID, nil

	case ChallengeKindAddCredential:
		if userID == "" {
			return "", errors.New("add-credential challenges require a user ID")
		}
		return string(kind) + ":" + userID, nil

	default:
		return "", fmt.Errorf("unsupported challenge kind '%s'", kind)
	}
}

// BeginChallenge stores a new WebAuthn challenge with its payload, encoded as JSON, and returns its ID
// userID binds the challenge to a user, and it's required for add-credential challenges
func (h *Host) BeginChallenge(ctx context.Context, kind ChallengeKind, userID string, expiresAt time.Time, payload []byte) (string, error) {
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(5 * time.Minute)
	}

	challengeID := uuid.NewV4().String()
	actorID, err := challengeActorID(kind, challengeID, userID)
	if err != nil {
		return "", err
	}

	_, err = invoke[struct{}](ctx, h, actorTypeChallenge, actorID, challengeMethodBegin, challengeBeginReq{
		State: challengeActorState{
			Kind:        kind,
			ChallengeID: challengeID,
			UserID:      userID,
			ExpiresAt:   expiresAt,
			Payload:     payload,
		},
	})
	if err != nil {
		return "", err
	}

	return challengeID, nil
}

// ConsumeChallenge returns the payload of a challenge, and deletes it so it can be used once only
// userID must match the user the challenge is bound to, and it's empty for sign-ins
// It returns ErrInvalidChallenge if the challenge doesn't exist, has expired, or doesn't match
func (h *Host) ConsumeChallenge(ctx context.Context, kind ChallengeKind, challengeID string, userID string) ([]byte, error) {
	actorID, err := challengeActorID(kind, challengeID, userID)
	if err != nil {
		return nil, err
	}

	res, err := invoke[challengeConsumeRes](ctx, h, actorTypeChallenge, actorID, challengeMethodConsume, challengeConsumeReq{
		Kind:        kind,
		ChallengeID: challengeID,
		UserID:      userID,
	})
	if err != nil {
		return nil, err
	}
	if !res.Found {
		return nil, ErrInvalidChallenge
	}

	return res.Payload, nil
}

// HasPendingAddCredentialChallenge returns true if the user has an add-credential challenge that hasn't been used and hasn't expired
func (h *Host) HasPendingAddCredentialChallenge(ctx context.Context, userID string) (bool, error) {
	actorID, err := challengeActorID(ChallengeKindAddCredential, "", userID)
	if err != nil {
		return false, err
	}

	res, err := peek[challengePendingRes](ctx, h, actorTypeChallenge, actorID, challengeMethodPending, nil)
	if err != nil {
		return false, err
	}

	return res.Pending, nil
}
