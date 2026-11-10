package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/italypaleale/francis/actor"

	"github.com/italypaleale/revaulter/internal/db"
)

const (
	// actorTypeSignup is the actor type that holds a signup until it's finalized, keyed by the WebAuthn user handle
	actorTypeSignup = "revaulter.signup"
	// signupActorCleanupAlarm is the name of the alarm that deletes a signup once it expires
	signupActorCleanupAlarm = "cleanup"
	// SignupRegisteredTTL is how long a signup with a registered passkey is kept before it must be finalized
	SignupRegisteredTTL = 24 * time.Hour
	// maxSignupIDLength is the maximum length of a signup ID sent by a client
	maxSignupIDLength = 128
)

// Methods of the revaulter.signup actor
const (
	signupMethodBegin    = "begin"
	signupMethodGet      = "get"
	signupMethodRegister = "register"
	signupMethodLogin    = "login"
	signupMethodFinalize = "finalize"
)

var (
	// ErrSignupNotFound is returned when a signup doesn't exist, has expired, or isn't in the phase the operation requires
	ErrSignupNotFound = errors.New("signup not found or expired")
	// ErrSignupAlreadyFinalized is returned when finalizing a signup whose user or passkey already exists
	ErrSignupAlreadyFinalized = errors.New("signup is already finalized")
)

// SignupPhase is the phase a signup is in
type SignupPhase string

const (
	// SignupPhaseBegun is set by register/begin, while the browser creates the passkey
	SignupPhaseBegun SignupPhase = "begun"
	// SignupPhaseRegistered is set by register/finish, once the passkey is verified, until the signup is finalized
	SignupPhaseRegistered SignupPhase = "registered"
)

// Signup is the state of an unfinished signup, kept in the revaulter.signup actor
// A user is added to the main database only when the signup is finalized
type Signup struct {
	Phase       SignupPhase
	UserID      string
	DisplayName string
	// WebAuthn user handle, base64url-encoded, which is also the ID of the actor
	WebAuthnUserID string
	// WebAuthn session data, encoded as JSON, while the signup is begun
	Session []byte
	// When the current phase expires
	ExpiresAt time.Time
	// The registered passkey
	Credential *SignupCredential
}

// SignupCredential is the passkey registered for a signup
type SignupCredential struct {
	// WebAuthn credential ID, base64url-encoded
	ID string
	// WebAuthn credential, encoded as JSON
	PublicKey string
	SignCount int64
}

// signupErrorCode is returned by the revaulter.signup actor when an operation can't be performed
type signupErrorCode string

const (
	signupErrNotFound         signupErrorCode = "not-found"
	signupErrAlreadyFinalized signupErrorCode = "already-finalized"
	signupErrInvalidLogin     signupErrorCode = "invalid-login"
)

type signupGetRes struct {
	Found  bool
	Signup Signup
}

type signupRegisterReq struct {
	Credential SignupCredential
	// Audit event to write with the registration, if any
	Audit *db.AuditEventInput
}

type signupLoginReq struct {
	CredentialID string
	SignCount    int64
	// Audit event to write with the sign-in, if any
	Audit *db.AuditEventInput
}

type signupFinalizeReq struct {
	Finalize db.FinalizeSignupInput
	// Audit event to write with the new user, if any
	Audit *db.AuditEventInput
}

type signupRes struct {
	Error  signupErrorCode
	Signup Signup
}

// testSignupMethods handles the methods of the revaulter.signup actor used by the e2e tests, returning false when the method isn't one of them
// This is only set in e2e builds
var testSignupMethods func(ctx context.Context, a *signupActor, method string, data actor.Envelope) (res any, handled bool, err error)

// signupActor is the revaulter.signup actor, which holds a registration that hasn't reached finalize-signup
type signupActor struct {
	host   *Host
	log    *slog.Logger
	client actor.Client[Signup]
}

// newSignupActor is the factory for revaulter.signup actors
func (h *Host) newSignupActor(actorID string, service *actor.Service) actor.Actor {
	return &signupActor{
		host:   h,
		log:    h.log.With(slog.String("actorType", actorTypeSignup), slog.String("signupId", actorID)),
		client: actor.NewActorClient[Signup](actorTypeSignup, actorID, service),
	}
}

// Invoke implements actor.ActorInvoke
func (a *signupActor) Invoke(ctx context.Context, method string, data actor.Envelope) (any, error) {
	switch method {
	case signupMethodBegin:
		var in Signup
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return nil, a.begin(ctx, in)

	case signupMethodRegister:
		var in signupRegisterReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.register(ctx, in)

	case signupMethodLogin:
		var in signupLoginReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.login(ctx, in)

	case signupMethodFinalize:
		var in signupFinalizeReq
		err := decodeActorEnvelope(data, &in)
		if err != nil {
			return nil, err
		}
		return a.finalize(ctx, in)

	}

	if testSignupMethods != nil {
		res, handled, err := testSignupMethods(ctx, a, method, data)
		if handled {
			return res, err
		}
	}

	return nil, fmt.Errorf("unsupported method '%s'", method)
}

// Peek implements actor.ActorPeek
func (a *signupActor) Peek(ctx context.Context, method string, _ actor.Envelope) (any, error) {
	if method != signupMethodGet {
		return nil, fmt.Errorf("unsupported method '%s'", method)
	}

	st, err := a.client.GetState(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load state: %w", err)
	}

	if !st.isActive(time.Now()) {
		return signupGetRes{}, nil
	}

	return signupGetRes{
		Found:  true,
		Signup: st,
	}, nil
}

// Alarm implements actor.ActorAlarm
func (a *signupActor) Alarm(ctx context.Context, name string, _ actor.Envelope) error {
	if name != signupActorCleanupAlarm {
		a.log.WarnContext(ctx, "Ignoring unknown alarm", slog.String("alarm", name))
		return nil
	}

	st, err := a.client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// A signup that moved to a later phase after this alarm was set has a later expiry
	if st.isActive(time.Now()) {
		return a.client.SetAlarm(ctx, signupActorCleanupAlarm, actor.AlarmProperties{DueTime: st.ExpiresAt})
	}

	err = a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		// Re-arm instead of returning an error, since Francis deletes an alarm once its retries run out
		a.log.WarnContext(ctx, "Failed to delete expired signup; will retry", slog.Any("error", err))
		return a.client.SetAlarm(ctx, signupActorCleanupAlarm, actor.AlarmProperties{DueTime: time.Now().Add(time.Minute)})
	}

	return nil
}

// isActive returns true if the signup exists and hasn't expired
func (st Signup) isActive(now time.Time) bool {
	return st.Phase != "" && now.Before(st.ExpiresAt)
}

// save stores the state and sets the cleanup alarm at its expiry
func (a *signupActor) save(ctx context.Context, st Signup) error {
	err := a.client.SetState(ctx, st, nil)
	if err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	err = a.client.SetAlarm(ctx, signupActorCleanupAlarm, actor.AlarmProperties{DueTime: st.ExpiresAt})
	if err != nil {
		return fmt.Errorf("failed to set cleanup alarm: %w", err)
	}

	return nil
}

// begin stores a new signup, with the WebAuthn session for creating its passkey
func (a *signupActor) begin(ctx context.Context, in Signup) error {
	in.Phase = SignupPhaseBegun
	in.Credential = nil
	return a.save(ctx, in)
}

// register stores the verified passkey and moves the signup to the registered phase
// This runs in a single turn, so a registration challenge can be used once only
func (a *signupActor) register(ctx context.Context, in signupRegisterReq) (signupRes, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return signupRes{}, fmt.Errorf("failed to load state: %w", err)
	}

	now := time.Now()
	if st.Phase != SignupPhaseBegun || !st.isActive(now) {
		return signupRes{Error: signupErrNotFound}, nil
	}

	if in.Audit != nil {
		_, err = a.host.db.AuditStore().Insert(ctx, *in.Audit)
		if err != nil {
			return signupRes{}, fmt.Errorf("failed to write audit event: %w", err)
		}
		a.host.NudgeAuditStream()
	}

	cred := in.Credential
	st.Phase = SignupPhaseRegistered
	st.Session = nil
	st.Credential = &cred
	st.ExpiresAt = now.Add(SignupRegisteredTTL)

	err = a.save(ctx, st)
	if err != nil {
		return signupRes{}, err
	}

	return signupRes{Signup: st}, nil
}

// login records a sign-in with the signup's passkey, updating its sign count
func (a *signupActor) login(ctx context.Context, in signupLoginReq) (signupRes, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return signupRes{}, fmt.Errorf("failed to load state: %w", err)
	}

	if st.Phase != SignupPhaseRegistered || !st.isActive(time.Now()) || st.Credential == nil || st.Credential.ID != in.CredentialID {
		return signupRes{Error: signupErrNotFound}, nil
	}

	// Check the current counter in the same turn that updates it, since login verification may have read an older snapshot
	// Zero counters are accepted for authenticators without a counter
	if in.SignCount != 0 && in.SignCount <= st.Credential.SignCount {
		return signupRes{Error: signupErrInvalidLogin}, nil
	}

	if in.Audit != nil {
		_, err = a.host.db.AuditStore().Insert(ctx, *in.Audit)
		if err != nil {
			return signupRes{}, fmt.Errorf("failed to write audit event: %w", err)
		}

		a.host.NudgeAuditStream()
	}

	cred := *st.Credential
	cred.SignCount = in.SignCount
	st.Credential = &cred

	err = a.client.SetState(ctx, st, nil)
	if err != nil {
		return signupRes{}, fmt.Errorf("failed to save state: %w", err)
	}

	return signupRes{Signup: st}, nil
}

// finalize creates the user and its passkey in the main database, with all the material generated at signup, then deletes the signup
func (a *signupActor) finalize(ctx context.Context, in signupFinalizeReq) (signupRes, error) {
	st, err := a.client.GetState(ctx)
	if err != nil {
		return signupRes{}, fmt.Errorf("failed to load state: %w", err)
	}

	if st.Phase != SignupPhaseRegistered || !st.isActive(time.Now()) || st.Credential == nil {
		return signupRes{Error: signupErrNotFound}, nil
	}

	// Create the user and mark it as ready in the same transaction, together with the audit event
	in.Finalize.UserID = st.UserID
	_, err = db.ExecuteInTransaction(ctx, a.host.db, 30*time.Second, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		as := tx.AuthStore()
		_, rErr := as.RegisterUser(ctx, db.RegisterUserInput{
			UserID:         st.UserID,
			DisplayName:    st.DisplayName,
			WebAuthnUserID: st.WebAuthnUserID,
			CredentialID:   st.Credential.ID,
			PublicKey:      st.Credential.PublicKey,
			SignCount:      st.Credential.SignCount,
		})
		if rErr != nil {
			return struct{}{}, rErr
		}

		_, rErr = as.FinalizeSignup(ctx, in.Finalize)
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
	if errors.Is(err, db.ErrUserAlreadyExists) || errors.Is(err, db.ErrAlreadyFinalized) {
		// The user or the passkey exists already, for example because a previous finalize committed but failed to delete the signup
		return signupRes{Error: signupErrAlreadyFinalized}, nil
	} else if err != nil {
		return signupRes{}, err
	}
	if in.Audit != nil {
		a.host.NudgeAuditStream()
	}

	// The user is in the main database now, so the signup isn't needed anymore
	// If this fails, the signup expires on its own, and a repeated finalize reports it's already finalized
	err = a.client.DeleteState(ctx)
	if err != nil && !errors.Is(err, actor.ErrStateNotFound) {
		a.log.WarnContext(ctx, "Failed to delete finalized signup", slog.Any("error", err))
	}
	err = a.client.DeleteAlarm(ctx, signupActorCleanupAlarm)
	if err != nil && !errors.Is(err, actor.ErrAlarmNotFound) {
		a.log.WarnContext(ctx, "Failed to delete cleanup alarm of finalized signup", slog.Any("error", err))
	}

	return signupRes{Signup: st}, nil
}

// SignupClient calls the revaulter.signup actor of a signup
type SignupClient struct {
	host *Host
	id   string
}

// Signup returns a client for the revaulter.signup actor of a signup
// The ID is the WebAuthn user handle, base64url-encoded
func (h *Host) Signup(signupID string) SignupClient {
	return SignupClient{
		host: h,
		id:   signupID,
	}
}

// validID returns true if the signup ID can be used as an actor ID
func (c SignupClient) validID() bool {
	return c.id != "" && len(c.id) <= maxSignupIDLength && !strings.ContainsRune(c.id, '/')
}

// Begin stores a new signup, with the WebAuthn session for creating its passkey, until in.ExpiresAt
func (c SignupClient) Begin(ctx context.Context, in Signup) error {
	if !c.validID() {
		return errors.New("invalid signup ID")
	}

	_, err := invoke[struct{}](ctx, c.host, actorTypeSignup, c.id, signupMethodBegin, in)
	return err
}

// Get returns the signup, or nil if it doesn't exist or has expired
func (c SignupClient) Get(ctx context.Context) (*Signup, error) {
	if !c.validID() {
		return nil, nil
	}

	res, err := peek[signupGetRes](ctx, c.host, actorTypeSignup, c.id, signupMethodGet, nil)
	if err != nil {
		return nil, err
	}
	if !res.Found {
		return nil, nil
	}

	return &res.Signup, nil
}

// Register stores the verified passkey for a begun signup, and writes the audit event, which is optional
// It returns ErrSignupNotFound if the signup doesn't exist, has expired, or already has a passkey
func (c SignupClient) Register(ctx context.Context, cred SignupCredential, audit *db.AuditEventInput) (*Signup, error) {
	return c.call(ctx, signupMethodRegister, signupRegisterReq{
		Credential: cred,
		Audit:      audit,
	})
}

// Login records a sign-in with the passkey of a registered signup, updating its sign count, and writes the audit event, which is optional
// It returns ErrSignupNotFound if the signup doesn't exist, has expired, or has a different passkey
// It returns db.ErrInvalidLogin if a non-zero authenticator counter does not increase
func (c SignupClient) Login(ctx context.Context, credentialID string, signCount int64, audit *db.AuditEventInput) (*Signup, error) {
	return c.call(ctx, signupMethodLogin, signupLoginReq{
		CredentialID: credentialID,
		SignCount:    signCount,
		Audit:        audit,
	})
}

// Finalize creates the user and its passkey in the main database, with all the material generated at signup, and writes the audit event, which is optional
// The user ID in the input is ignored and replaced with the signup's
// It returns ErrSignupNotFound if the signup doesn't exist or has expired, and ErrSignupAlreadyFinalized if the user or the passkey already exists
func (c SignupClient) Finalize(ctx context.Context, in db.FinalizeSignupInput, audit *db.AuditEventInput) (*Signup, error) {
	return c.call(ctx, signupMethodFinalize, signupFinalizeReq{
		Finalize: in,
		Audit:    audit,
	})
}

func (c SignupClient) call(ctx context.Context, method string, data any) (*Signup, error) {
	if !c.validID() {
		return nil, ErrSignupNotFound
	}

	res, err := invoke[signupRes](ctx, c.host, actorTypeSignup, c.id, method, data)
	if err != nil {
		return nil, err
	}

	switch res.Error {
	case signupErrNotFound:
		return nil, ErrSignupNotFound
	case signupErrAlreadyFinalized:
		return nil, ErrSignupAlreadyFinalized
	case signupErrInvalidLogin:
		return nil, db.ErrInvalidLogin
	}

	return &res.Signup, nil
}
