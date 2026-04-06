package v2db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	sqlutilsmigrations "github.com/italypaleale/go-sql-utils/migrations"
	pgmigrations "github.com/italypaleale/go-sql-utils/migrations/postgres"
	sqlitemigrations "github.com/italypaleale/go-sql-utils/migrations/sqlite"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	v2MigrationMetadataTable = "metadata"
	v2MigrationMetadataKey   = "migrations"
)

var (
	//go:embed migrations/sqlite/*.sql
	sqliteMigrations embed.FS
	//go:embed migrations/postgres/*.sql
	postgresMigrations embed.FS
)

type migrationScript struct {
	name string
	sql  string
}

// RunMigrations executes the full schema migration sequence.
func RunMigrations(ctx context.Context, conn *DB, logger *slog.Logger) error {
	if conn == nil {
		return errors.New("db connection is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	switch conn.Backend {
	case BackendPostgres:
		return runPostgresMigrations(ctx, conn.Postgres, logger)
	case BackendSQLite:
		return runSQLiteMigrations(ctx, conn.SQLite, logger)
	default:
		return errors.New("unsupported backend")
	}
}

func runPostgresMigrations(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	if db == nil {
		return errors.New("postgres pool is nil")
	}

	scripts, err := loadMigrationScripts(postgresMigrations, "postgres")
	if err != nil {
		return err
	}

	m := &pgmigrations.Migrations{
		DB:                db,
		MetadataTableName: v2MigrationMetadataTable,
		MetadataKey:       v2MigrationMetadataKey,
	}
	return m.Perform(ctx, postgresMigrationFns(m, scripts), logger)
}

func runSQLiteMigrations(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	if db == nil {
		return errors.New("sqlite db is nil")
	}

	scripts, err := loadMigrationScripts(sqliteMigrations, "sqlite")
	if err != nil {
		return err
	}

	m := &sqlitemigrations.Migrations{
		Pool:              db,
		MetadataTableName: v2MigrationMetadataTable,
		MetadataKey:       v2MigrationMetadataKey,
	}
	return m.Perform(ctx, sqliteMigrationFns(m, scripts), logger)
}

func loadMigrationScripts(migrationsFS embed.FS, driver string) ([]migrationScript, error) {
	dir := "migrations/" + driver
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded migrations from %q: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	scripts := make([]migrationScript, 0, len(names))
	for _, name := range names {
		path := dir + "/" + name
		data, err := migrationsFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded migration %q: %w", path, err)
		}

		sql := strings.TrimSpace(string(data))
		if sql == "" {
			continue
		}

		scripts = append(scripts, migrationScript{
			name: name,
			sql:  sql,
		})
	}

	if len(scripts) == 0 {
		return nil, fmt.Errorf("no embedded SQL migrations found in %q", dir)
	}
	return scripts, nil
}

func postgresMigrationFns(m *pgmigrations.Migrations, scripts []migrationScript) []sqlutilsmigrations.MigrationFn {
	fns := make([]sqlutilsmigrations.MigrationFn, len(scripts))
	for i, script := range scripts {
		fns[i] = func(ctx context.Context) error {
			_, err := m.DB.Exec(ctx, script.sql)
			if err != nil {
				return fmt.Errorf("postgres migration %q failed: %w", script.name, err)
			}
			return nil
		}
	}
	return fns
}

func sqliteMigrationFns(m *sqlitemigrations.Migrations, scripts []migrationScript) []sqlutilsmigrations.MigrationFn {
	fns := make([]sqlutilsmigrations.MigrationFn, len(scripts))
	for i, script := range scripts {
		fns[i] = func(ctx context.Context) error {
			_, err := m.GetConn().ExecContext(ctx, script.sql)
			if err != nil {
				return fmt.Errorf("sqlite migration %q failed: %w", script.name, err)
			}
			return nil
		}
	}
	return fns
}
