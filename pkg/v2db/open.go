package v2db

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
	"github.com/jackc/pgx/v5/pgxpool"
)

type BackendKind string

const (
	BackendSQLite   BackendKind = "sqlite"
	BackendPostgres BackendKind = "postgres"
)

type DB struct {
	kind BackendKind
	db   adapter.DatabaseConn
	sql  *sql.DB
	pgx  *pgxpool.Pool
}

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

	db.db = nil

	return nil
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
			kind: BackendPostgres,
			pgx:  conn,
			db:   postgresadapter.AdaptPgxConn(conn),
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
			kind: BackendSQLite,
			sql:  conn,
			db:   sqladapter.AdaptDatabaseSQLConn(conn),
		}, nil
	}
}
