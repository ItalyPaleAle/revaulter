package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/italypaleale/francis/host/local"
	sqliteutils "github.com/italypaleale/go-sql-utils/sqlite"

	"github.com/italypaleale/revaulter/internal/config"
	"github.com/italypaleale/revaulter/internal/db"
)

// storeKind is the kind of data store used by the Francis host
type storeKind string

const (
	storeSQLite   storeKind = "sqlite"
	storePostgres storeKind = "postgres"
	storeMemory   storeKind = "memory"
)

// store is where the Francis host keeps its data
type store struct {
	kind storeKind
	// Connection string for SQLite and Postgres
	dsn string
}

// resolveStore returns where the Francis host keeps its data
// When `francisDatabaseDSN` is empty, the store is derived from `databaseDSN`: a separate schema for Postgres, or a sibling file for SQLite
func resolveStore(cfg *config.Config) (store, error) {
	dsn := strings.TrimSpace(cfg.FrancisDatabaseDSN)
	derived := false
	if dsn == "" {
		derived = true
		dsn = strings.TrimSpace(cfg.DatabaseDSN)
	}
	if dsn == "" {
		return store{}, errors.New("connection string for the Francis database is empty")
	}

	// Postgres uses a dedicated schema, which works for both the main database and a separate one
	if db.IsPostgresConnectionString(dsn) {
		return store{
			kind: storePostgres,
			dsn:  dsn,
		}, nil
	}

	// We have a SQLite database
	_, dbPath, isMemory, _, err := sqliteutils.ParseConnectionString(dsn, slog.New(slog.DiscardHandler))
	if err != nil {
		return store{}, fmt.Errorf("invalid connection string for the Francis database: %w", err)
	}

	// An in-memory main database, which is used in tests, gets an in-memory Francis store
	if isMemory {
		return store{
			kind: storeMemory,
		}, nil
	}

	// An explicit SQLite connection string is used as-is
	if !derived {
		return store{
			kind: storeSQLite,
			dsn:  dsn,
		}, nil
	}

	// Store the Francis data in a file next to the main database
	// For example, "/data/revaulter.db" becomes "/data/revaulter.francis.db"
	base := filepath.Base(dbPath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return store{
		kind: storeSQLite,
		dsn:  filepath.Join(filepath.Dir(dbPath), base+".francis.db"),
	}, nil
}

// hostOption returns the option that configures the Francis provider for the store
func (s store) hostOption() local.HostOption {
	switch s.kind {
	case storePostgres:
		return local.WithPostgresProvider(local.PostgresProviderOptions{
			ConnectionString: s.dsn,
			Schema:           "francis",
		})
	case storeSQLite:
		return local.WithSQLiteProvider(local.SQLiteProviderOptions{
			ConnectionString: s.dsn,
		})
	default:
		return local.WithStandaloneMemoryProvider(local.StandaloneMemoryProviderOptions{})
	}
}

// prepare performs the setup the store needs before the Francis host can start
func (s store) prepare(ctx context.Context) error {
	if s.kind != storePostgres {
		return nil
	}

	// The Postgres provider requires the schema to exist
	return db.EnsurePostgresSchema(ctx, s.dsn, "francis")
}
