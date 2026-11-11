// Package actors runs the embedded Francis host and the actors for Revaulter
// Every replica runs a host
package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/italypaleale/francis/actor"
	"github.com/italypaleale/francis/builtin/signal"
	"github.com/italypaleale/francis/host/local"
	"github.com/italypaleale/go-kit/servicerunner"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/metrics"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

// ErrHostNotRunning is returned when an actor is called while the Francis host isn't running
var ErrHostNotRunning = errors.New("the Francis host is not running")

// Host is the embedded Francis host, with the actor types and signal sets that Revaulter registers on it
type Host struct {
	host  *local.Host
	store store
	db    *db.DB
	log   *slog.Logger

	// Audit log stream, which runs on the host where the revaulter.audit actor is active
	// Nil when `auditStreamUrl` is not configured
	auditStream *auditStream
	// Nudges for an audit log stream that runs on another host
	auditNudges chan struct{}

	// Sends the notifications for new requests
	// Nil when notifications are not enabled
	notifier Notifier

	// Signals that wake the long-polls waiting for a result, and the list streams waiting for changes
	waiters *signal.SignalService
	inbox   *signal.SignalService

	// Set while the host accepts calls
	running atomic.Bool
	// Closed once the host accepts calls
	ready     chan struct{}
	readyOnce sync.Once
}

// NewHostOptions contains the options for NewHost
type NewHostOptions struct {
	Log     *slog.Logger
	DB      *db.DB
	Metrics *metrics.RevaulterMetrics

	// Sends the notifications for new requests
	// It's optional, and when it's nil, no notification is sent
	Notifier Notifier
}

// NewHost creates the Francis host from the configuration, and registers the actor types and the signal sets on it
// The host must then be started with Run
func NewHost(opts NewHostOptions) (*Host, error) {
	cfg := config.Get()

	if opts.DB == nil {
		return nil, errors.New("option DB is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	psk := cfg.FrancisPSK()
	if len(psk) == 0 {
		return nil, errors.New("the Francis cluster key is not set")
	}

	st, err := resolveStore(cfg)
	if err != nil {
		return nil, err
	}

	hostOpts := []local.HostOption{
		local.WithAddress(cfg.FrancisPeerAddress),
		local.WithRuntimePSKs(psk),
		local.WithLogger(opts.Log.With(slog.String("component", "francis"))),
		local.WithShutdownGracePeriod(10 * time.Second),
		st.hostOption(),
	}
	if cfg.FrancisBindPort > 0 {
		hostOpts = append(hostOpts, local.WithBindPort(cfg.FrancisBindPort))
	}

	lh, err := local.NewHost(hostOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Francis host: %w", err)
	}

	auditStream, err := newAuditStream(opts.DB, opts.Metrics, opts.Log)
	if err != nil {
		return nil, err
	}

	h := &Host{
		host:        lh,
		store:       st,
		db:          opts.DB,
		log:         opts.Log,
		auditStream: auditStream,
		auditNudges: make(chan struct{}, 1),
		notifier:    opts.Notifier,
		ready:       make(chan struct{}),
	}

	err = h.register()
	if err != nil {
		return nil, err
	}

	return h, nil
}

// register registers the actor types and the signal sets on the Francis host
func (h *Host) register() error {
	// waiters wakes the long-polls waiting for the result of a request
	// A completion is kept for a while, so a waiter that arrives after the signal fired is still answered right away
	waiters, err := signal.New("revaulter-waiters", signal.WithRetention(15*time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create signal set '%s': %w", "revaulter-waiters", err)
	}
	err = h.host.RegisterBuiltInActor(waiters)
	if err != nil {
		return fmt.Errorf("failed to register signal set '%s': %w", "revaulter-waiters", err)
	}
	h.waiters = waiters.Service(h.host.Service())

	// inbox wakes the list streams of a user when the pending requests change
	inbox, err := signal.New("revaulter-inbox", signal.WithRetention(10*time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create signal set '%s': %w", "revaulter-inbox", err)
	}
	err = h.host.RegisterBuiltInActor(inbox)
	if err != nil {
		return fmt.Errorf("failed to register signal set '%s': %w", "revaulter-inbox", err)
	}
	h.inbox = inbox.Service(h.host.Service())

	// Register the revaulter.user actor
	err = h.host.RegisterActor(actorTypeUser, h.newUserActor)
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypeUser, err)
	}

	// Register the revaulter.challenge actor
	err = h.host.RegisterActor(actorTypeChallenge, h.newChallengeActor, local.WithIdleTimeout(challengeActorIdleTimeout))
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypeChallenge, err)
	}

	// Register the revaulter.pairing actor
	err = h.host.RegisterActor(actorTypePairing, h.newPairingActor, local.WithIdleTimeout(pairingActorIdleTimeout))
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypePairing, err)
	}

	// Register the revaulter.signup actor
	err = h.host.RegisterActor(actorTypeSignup, h.newSignupActor)
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypeSignup, err)
	}

	// Register the revaulter.notifier actor, when notifications are enabled
	// Its jobs are retried when sending a notification fails
	if h.notifier != nil {
		err = h.host.RegisterActor(actorTypeNotifier, h.newNotifierActor,
			// Francis v0.2.1 counts attempts from 0 and gives up only once the count exceeds this value, so it allows one more attempt than it's set to
			local.WithMaxAttempts(notifierMaxAttempts-1),
			local.WithInitialRetryDelay(notifierInitialRetryDelay),
			local.WithDeadLetteredJobRetention(notifierDeadLetteredRetention),
		)
		if err != nil {
			return fmt.Errorf("failed to register actor type '%s': %w", actorTypeNotifier, err)
		}
	}

	// Register the revaulter.audit singleton actor
	// While the audit log stream is enabled, the actor stays active, so the stream keeps running on the host that holds it
	var auditOpts []local.RegisterActorOption
	if h.auditStream != nil {
		auditOpts = append(auditOpts, local.WithIdleTimeout(-1))
	}
	err = h.host.RegisterSingletonActor(actorTypeAudit, h.newAuditActor, auditOpts...)
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypeAudit, err)
	}

	return nil
}

// Ready returns a channel that is closed once the host has started and accepts calls
func (h *Host) Ready() <-chan struct{} {
	return h.ready
}

// checkRunning returns ErrHostNotRunning if the host doesn't accept calls
// Francis can't take calls before it has started, so every call must check this first
func (h *Host) checkRunning() error {
	if !h.running.Load() {
		return ErrHostNotRunning
	}
	return nil
}

// Run the Francis host until ctx is canceled
// It's meant to run in a service runner: ready is signaled once the host accepts calls, so the services that call actors can wait for it with ready.Await
// After ctx is canceled, the host keeps running until drained is signaled, so in-flight requests can still call actors while the app server drains
// The services that wait on ready must signal drained whenever they return, even if they never started, or the host never stops
// Both ready and drained can be nil
func (h *Host) Run(ctx context.Context, ready *servicerunner.Ready, drained *servicerunner.Ready) error {
	err := h.store.prepare(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare the Francis database: %w", err)
	}

	// The host runs on its own context, which is canceled only once the app has drained
	hostCtx, hostCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer hostCancel()
	hostErrCh := make(chan error, 1)
	go func() {
		hostErrCh <- h.host.Run(hostCtx)
	}()

	select {
	case <-h.host.Ready():
		logging.LogFromContext(ctx).InfoContext(ctx, "Francis host started",
			slog.String("peerAddress", config.Get().FrancisPeerAddress),
			slog.String("store", string(h.store.kind)),
		)
		h.running.Store(true)
		h.readyOnce.Do(func() {
			close(h.ready)
		})
		if ready != nil {
			ready.Signal()
		}
	case err = <-hostErrCh:
		return fmt.Errorf("the Francis host stopped before becoming ready: %w", err)
	case <-ctx.Done():
		hostCancel()
		<-hostErrCh
		return ctx.Err()
	}

	// Send the nudges for an audit log stream that runs on another host
	nudgerCtx, nudgerCancel := context.WithCancel(hostCtx)
	defer nudgerCancel()
	var nudgerWg sync.WaitGroup
	if h.auditStream != nil {
		nudgerWg.Go(func() {
			h.runAuditNudger(nudgerCtx)
		})
	}

	// Make sure the audit log stream stops with the host, even if the host didn't deactivate the revaulter.audit actor
	defer func() {
		nudgerCancel()
		nudgerWg.Wait()
		if h.auditStream != nil {
			h.auditStream.stop()
		}
	}()

	select {
	case <-ctx.Done():
		// The app is shutting down
	case err = <-hostErrCh:
		h.running.Store(false)
		return fmt.Errorf("the Francis host stopped unexpectedly: %w", err)
	}

	// Wait for the app to drain before stopping the host
	if drained != nil {
		_ = drained.Await(func(context.Context) error { return nil })(context.Background())
	}

	h.running.Store(false)
	hostCancel()
	err = <-hostErrCh
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("error stopping the Francis host: %w", err)
	}

	return nil
}

// invoke invokes a method of an actor, and decodes the response
func invoke[T any](ctx context.Context, h *Host, actorType string, actorID string, method string, data any) (res T, err error) {
	err = h.checkRunning()
	if err != nil {
		return res, err
	}

	env, err := h.host.Service().Invoke(ctx, actorType, actorID, method, data)
	if err != nil {
		return res, fmt.Errorf("failed to invoke method '%s' of actor '%s': %w", method, actorType, err)
	}

	return decodeResponse[T](env, actorType, method)
}

// peek performs a read-only call to a method of an actor, and decodes the response
func peek[T any](ctx context.Context, h *Host, actorType string, actorID string, method string, data any) (res T, err error) {
	err = h.checkRunning()
	if err != nil {
		return res, err
	}

	env, err := h.host.Service().Peek(ctx, actorType, actorID, method, data)
	if err != nil {
		return res, fmt.Errorf("failed to peek method '%s' of actor '%s': %w", method, actorType, err)
	}

	return decodeResponse[T](env, actorType, method)
}

func decodeResponse[T any](env actor.Envelope, actorType string, method string) (res T, err error) {
	if env == nil {
		return res, nil
	}

	err = env.Decode(&res)
	if err != nil {
		return res, fmt.Errorf("failed to decode response of method '%s' of actor '%s': %w", method, actorType, err)
	}

	return res, nil
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
