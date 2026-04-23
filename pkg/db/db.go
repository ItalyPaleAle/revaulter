package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"
	postgresadapter "github.com/italypaleale/go-sql-utils/adapter/postgres"
	sqladapter "github.com/italypaleale/go-sql-utils/adapter/sql"
	sqliteutils "github.com/italypaleale/go-sql-utils/sqlite"
	transactions "github.com/italypaleale/go-sql-utils/transactions/adapter"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/jackc/pgx/v5/pgxpool"
)

type BackendKind string

const (
	BackendSQLite   BackendKind = "sqlite"
	BackendPostgres BackendKind = "postgres"
)

type DB struct {
	adapter.DatabaseConn

	kind BackendKind
	sql  *sql.DB
	pgx  *pgxpool.Pool
}

// Kind returns the backend kind for this connection
func (db *DB) Kind() BackendKind {
	return db.kind
}

// Close the database connection
// Implements io.Closer
func (db *DB) Close(_ context.Context) error {
	// Close the connection
	if db.sql != nil {
		err := db.sql.Close()
		if err != nil {
			return fmt.Errorf("error closing database connection: %w", err)
		}
		db.sql = nil
	}

	if db.pgx != nil {
		db.pgx.Close()
		db.pgx = nil
	}

	db.DatabaseConn = nil

	return nil
}

// AuthStore returns an instance of AuthStore
func (db *DB) AuthStore() *AuthStore {
	as, err := NewAuthStore(db, db.kind)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// RequestStore returns an instance of RequestStore
func (db *DB) RequestStore() *RequestStore {
	as, err := NewRequestStore(db)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// SigningKeyStore returns an instance of SigningKeyStore
func (db *DB) SigningKeyStore() *SigningKeyStore {
	as, err := NewSigningKeyStore(db)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

type dbTx struct {
	adapter.Querier

	kind BackendKind
}

// AuthStore returns an instance of AuthStore
/*func (tx *dbTx) AuthStore() *AuthStore {
	as, err := NewAuthStore(tx, tx.kind)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}*/

// RequestStore returns an instance of RequestStore
func (tx *dbTx) RequestStore() *RequestStore {
	as, err := NewRequestStore(tx)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// SigningKeyStore returns an instance of SigningKeyStore
func (tx *dbTx) SigningKeyStore() *SigningKeyStore {
	as, err := NewSigningKeyStore(tx)
	if err != nil {
		// Indicates a development-time error
		panic(err)
	}

	return as
}

// Note that the timeout for pgx is tied to the begin command only, while it's tied to the entire transaction for SQL adapters
func (db *DB) ExecuteInTransaction(ctx context.Context, timeout time.Duration, fn func(ctx context.Context, tx *dbTx) error) error {
	_, err := transactions.ExecuteInTransaction(ctx, logging.LogFromContext(ctx), db.DatabaseConn, timeout, func(ctx context.Context, tx adapter.Querier) (struct{}, error) {
		wrapped := &dbTx{
			Querier: tx,
			kind:    db.kind,
		}
		return struct{}{}, fn(ctx, wrapped)
	})
	return err
}

// Open the connection
func Open(ctx context.Context, connString string) (*DB, error) {
	connString = strings.TrimSpace(connString)
	if connString == "" {
		return nil, errors.New("connection string is empty")
	}

	switch {
	// Postgres connection strings begin with "postgres://" or "postgresql://"
	case strings.HasPrefix(connString, "postgres://"), strings.HasPrefix(connString, "postgresql://"):
		cfg, err := pgxpool.ParseConfig(connString)
		if err != nil {
			return nil, fmt.Errorf("invalid Postgres connection string: %w", err)
		}
		if cfg.ConnConfig.ConnectTimeout == 0 {
			cfg.ConnConfig.ConnectTimeout = 10 * time.Second
		}
		conn, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Postgres: %w", err)
		}
		return &DB{
			kind:         BackendPostgres,
			pgx:          conn,
			DatabaseConn: postgresadapter.AdaptPgxConn(conn),
		}, nil

	// Default to sqlite
	default:
		conn, err := sqliteutils.Connect(sqliteutils.ConnectOpts{
			ConnString: connString,
			Logger:     slog.Default().With(slog.String("component", "sqliteutils")),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite database: %w", err)
		}
		return &DB{
			kind:         BackendSQLite,
			sql:          conn,
			DatabaseConn: sqladapter.AdaptDatabaseSQLConn(conn),
		}, nil
	}
}
