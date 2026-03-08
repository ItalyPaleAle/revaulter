package v2db

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	sqlutilsmigrations "github.com/italypaleale/go-sql-utils/migrations"
	pgmigrations "github.com/italypaleale/go-sql-utils/migrations/postgres"
	sqlitemigrations "github.com/italypaleale/go-sql-utils/migrations/sqlite"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations executes migrations using go-sql-utils wrappers.
func RunMigrations(ctx context.Context, conn *DB, migrationFns []sqlutilsmigrations.MigrationFn, logger *slog.Logger) error {
	if conn == nil {
		return errors.New("db connection is nil")
	}
	switch conn.Backend {
	case BackendPostgres:
		return runPostgresMigrations(ctx, conn.Postgres, migrationFns, logger)
	case BackendSQLite:
		return runSQLiteMigrations(ctx, conn.SQLite, migrationFns, logger)
	default:
		return errors.New("unsupported backend")
	}
}

func runPostgresMigrations(ctx context.Context, db *pgxpool.Pool, migrationFns []sqlutilsmigrations.MigrationFn, logger *slog.Logger) error {
	if db == nil {
		return errors.New("postgres pool is nil")
	}
	m := pgmigrations.Migrations{
		DB:                db,
		MetadataTableName: "_revaulter_v2_migrations",
		MetadataKey:       "schema",
	}
	return m.Perform(ctx, migrationFns, logger)
}

func runSQLiteMigrations(ctx context.Context, db *sql.DB, migrationFns []sqlutilsmigrations.MigrationFn, logger *slog.Logger) error {
	if db == nil {
		return errors.New("sqlite db is nil")
	}
	m := sqlitemigrations.Migrations{
		Pool:              db,
		MetadataTableName: "_revaulter_v2_migrations",
		MetadataKey:       "schema",
	}
	return m.Perform(ctx, migrationFns, logger)
}
