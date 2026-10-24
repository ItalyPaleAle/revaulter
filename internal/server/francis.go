package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/italypaleale/francis/builtin/signal"
	"github.com/italypaleale/francis/host/local"
	sqliteutils "github.com/italypaleale/go-sql-utils/sqlite"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
	"github.com/italypaleale/revaulter/internal/utils/logging"
)

const (
	// francisPostgresSchema is the Postgres schema that holds the Francis tables
	francisPostgresSchema = "francis"
	// francisSQLiteExtension replaces the extension of the main SQLite file to get the name of the Francis one
	francisSQLiteExtension = ".francis.db"
	// francisShutdownGracePeriod is how long the Francis host waits for actors to deactivate when stopping
	francisShutdownGracePeriod = 10 * time.Second
)

// francisStoreKind is the kind of data store used by the Francis host
type francisStoreKind string

const (
	francisStoreSQLite   francisStoreKind = "sqlite"
	francisStorePostgres francisStoreKind = "postgres"
	francisStoreMemory   francisStoreKind = "memory"
)

// francisStore is where the Francis host keeps its data
type francisStore struct {
	kind francisStoreKind
	// Connection string for SQLite and Postgres
	dsn string
}

// resolveFrancisStore returns where the Francis host keeps its data
// When `francisDatabaseDSN` is empty, the store is derived from `databaseDSN`: a separate schema for Postgres, or a sibling file for SQLite
func resolveFrancisStore(cfg *config.Config) (francisStore, error) {
	dsn := strings.TrimSpace(cfg.FrancisDatabaseDSN)
	derived := dsn == ""
	if derived {
		dsn = strings.TrimSpace(cfg.DatabaseDSN)
	}
	if dsn == "" {
		return francisStore{}, errors.New("connection string for the Francis database is empty")
	}

	// Postgres uses a dedicated schema, which works for both the main database and a separate one
	if db.IsPostgresConnectionString(dsn) {
		return francisStore{
			kind: francisStorePostgres,
			dsn:  dsn,
		}, nil
	}

	_, dbPath, isMemory, _, err := sqliteutils.ParseConnectionString(dsn, slog.New(slog.DiscardHandler))
	if err != nil {
		return francisStore{}, fmt.Errorf("invalid connection string for the Francis database: %w", err)
	}

	// An in-memory main database, which is used in tests, gets an in-memory Francis store
	if isMemory {
		return francisStore{
			kind: francisStoreMemory,
		}, nil
	}

	// An explicit SQLite connection string is used as-is
	if !derived {
		return francisStore{
			kind: francisStoreSQLite,
			dsn:  dsn,
		}, nil
	}

	// Store the Francis data in a file next to the main database
	// For example, "/data/revaulter.db" becomes "/data/revaulter.francis.db"
	base := filepath.Base(dbPath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return francisStore{
		kind: francisStoreSQLite,
		dsn:  filepath.Join(filepath.Dir(dbPath), base+francisSQLiteExtension),
	}, nil
}

// hostOption returns the option that configures the Francis provider for the store
func (fs francisStore) hostOption() local.HostOption {
	switch fs.kind {
	case francisStorePostgres:
		return local.WithPostgresProvider(local.PostgresProviderOptions{
			ConnectionString: fs.dsn,
			Schema:           francisPostgresSchema,
		})
	case francisStoreSQLite:
		return local.WithSQLiteProvider(local.SQLiteProviderOptions{
			ConnectionString: fs.dsn,
		})
	default:
		return local.WithStandaloneMemoryProvider(local.StandaloneMemoryProviderOptions{})
	}
}

// prepare performs the setup the store needs before the Francis host can start
func (fs francisStore) prepare(ctx context.Context) error {
	if fs.kind != francisStorePostgres {
		return nil
	}

	// The Postgres provider requires the schema to exist
	return db.EnsurePostgresSchema(ctx, fs.dsn, francisPostgresSchema)
}

// newFrancisHost creates the embedded Francis host
// Actors must be registered on the host before it's started by runFrancis
func newFrancisHost(log *slog.Logger, store francisStore) (*local.Host, error) {
	cfg := config.Get()

	psk := cfg.FrancisPSK()
	if len(psk) == 0 {
		return nil, errors.New("the Francis cluster key is not set")
	}

	opts := []local.HostOption{
		local.WithAddress(cfg.FrancisPeerAddress),
		local.WithRuntimePSKs(psk),
		local.WithLogger(log.With(slog.String("component", "francis"))),
		local.WithShutdownGracePeriod(francisShutdownGracePeriod),
		store.hostOption(),
	}
	if cfg.FrancisBindPort > 0 {
		opts = append(opts, local.WithBindPort(cfg.FrancisBindPort))
	}

	host, err := local.NewHost(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Francis host: %w", err)
	}

	return host, nil
}

// registerActors registers the actor types and the signal sets on the Francis host
// This must be called before the host is started
func (s *Server) registerActors(log *slog.Logger) error {
	// A completion is kept for a while, so a waiter that arrives after the signal fired is still answered right away
	waiters, err := signal.New(signalSetWaiters, signal.WithRetention(15*time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create signal set '%s': %w", signalSetWaiters, err)
	}
	err = s.francis.RegisterBuiltInActor(waiters)
	if err != nil {
		return fmt.Errorf("failed to register signal set '%s': %w", signalSetWaiters, err)
	}
	s.waiters = waiters.Service(s.francis.Service())

	inbox, err := signal.New(signalSetInbox, signal.WithRetention(10*time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create signal set '%s': %w", signalSetInbox, err)
	}
	err = s.francis.RegisterBuiltInActor(inbox)
	if err != nil {
		return fmt.Errorf("failed to register signal set '%s': %w", signalSetInbox, err)
	}
	s.inbox = inbox.Service(s.francis.Service())

	err = s.francis.RegisterActor(actorTypeUser, s.newUserActorFactory(log))
	if err != nil {
		return fmt.Errorf("failed to register actor type '%s': %w", actorTypeUser, err)
	}

	return nil
}

// invokeUserActor invokes a method of the revaulter.user actor of a user, and decodes the response
func invokeUserActor[T any](ctx context.Context, s *Server, userID string, method string, data any) (res T, err error) {
	env, err := s.francis.Service().Invoke(ctx, actorTypeUser, userID, method, data)
	if err != nil {
		return res, fmt.Errorf("failed to invoke method '%s' of the user actor: %w", method, err)
	}

	if env != nil {
		err = env.Decode(&res)
		if err != nil {
			return res, fmt.Errorf("failed to decode response of method '%s' of the user actor: %w", method, err)
		}
	}

	return res, nil
}

// peekUserActor performs a read-only call to a method of the revaulter.user actor of a user, and decodes the response
func peekUserActor[T any](ctx context.Context, s *Server, userID string, method string, data any) (res T, err error) {
	env, err := s.francis.Service().Peek(ctx, actorTypeUser, userID, method, data)
	if err != nil {
		return res, fmt.Errorf("failed to peek method '%s' of the user actor: %w", method, err)
	}

	if env != nil {
		err = env.Decode(&res)
		if err != nil {
			return res, fmt.Errorf("failed to decode response of method '%s' of the user actor: %w", method, err)
		}
	}

	return res, nil
}

// francisRun is a running Francis host
type francisRun struct {
	cancel context.CancelFunc
	// done is closed when the host has stopped, after err is set
	done chan struct{}
	err  error
}

// Stop the Francis host and wait for it to return
func (r *francisRun) Stop() error {
	r.cancel()
	<-r.done

	if errors.Is(r.err, context.Canceled) {
		return nil
	}
	return r.err
}

// runFrancis starts the Francis host in background, and returns once it's ready to accept calls
func (s *Server) runFrancis(ctx context.Context) (*francisRun, error) {
	err := s.francisStore.prepare(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare the Francis database: %w", err)
	}

	// The host runs on its own context, so it keeps serving calls while the app server drains after ctx is canceled
	hostCtx, hostCancel := context.WithCancel(context.WithoutCancel(ctx))
	run := &francisRun{
		cancel: hostCancel,
		done:   make(chan struct{}),
	}
	go func() {
		run.err = s.francis.Run(hostCtx)
		close(run.done)
	}()

	select {
	case <-s.francis.Ready():
		logging.LogFromContext(ctx).InfoContext(ctx, "Francis host started",
			slog.String("peerAddress", config.Get().FrancisPeerAddress),
			slog.String("store", string(s.francisStore.kind)),
		)
		return run, nil
	case <-run.done:
		hostCancel()
		return nil, fmt.Errorf("the Francis host stopped before becoming ready: %w", run.err)
	case <-ctx.Done():
		_ = run.Stop()
		return nil, ctx.Err()
	}
}
