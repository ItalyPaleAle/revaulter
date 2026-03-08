package v2db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"
)

type DB struct {
	Backend  BackendKind
	SQLite   *sql.DB
	Postgres *pgxpool.Pool
}

func (db *DB) Close() error {
	switch db.Backend {
	case BackendPostgres:
		if db.Postgres != nil {
			db.Postgres.Close()
		}
		return nil
	case BackendSQLite:
		if db.SQLite != nil {
			return db.SQLite.Close()
		}
		return nil
	default:
		return nil
	}
}

func Open(ctx context.Context, rawDSN string) (*DB, ParsedDSN, error) {
	parsed, err := InferDSN(rawDSN)
	if err != nil {
		return nil, ParsedDSN{}, err
	}

	switch parsed.Backend {
	case BackendPostgres:
		cfg, err := pgxpool.ParseConfig(parsed.PostgresDSN)
		if err != nil {
			return nil, ParsedDSN{}, fmt.Errorf("invalid postgres DSN: %w", err)
		}
		if cfg.ConnConfig.ConnectTimeout == 0 {
			cfg.ConnConfig.ConnectTimeout = 10 * time.Second
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			return nil, ParsedDSN{}, err
		}
		return &DB{Backend: BackendPostgres, Postgres: pool}, parsed, nil
	case BackendSQLite:
		if err := ensureSQLiteDir(parsed.SQLitePath); err != nil {
			return nil, ParsedDSN{}, err
		}
		sqldb, err := sql.Open("sqlite", parsed.SQLitePath)
		if err != nil {
			return nil, ParsedDSN{}, err
		}
		if err := configureSQLite(ctx, sqldb); err != nil {
			_ = sqldb.Close()
			return nil, ParsedDSN{}, err
		}
		return &DB{Backend: BackendSQLite, SQLite: sqldb}, parsed, nil
	default:
		return nil, ParsedDSN{}, errors.New("unsupported backend")
	}
}

func ensureSQLiteDir(path string) error {
	if path == "" {
		return errors.New("sqlite path is empty")
	}
	// Skip special in-memory modes.
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return nil
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func configureSQLite(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("sqlite db is nil")
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON;"); err != nil {
		return fmt.Errorf("failed to enable SQLite foreign_keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000;"); err != nil {
		return fmt.Errorf("failed to set SQLite busy_timeout: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous=NORMAL;"); err != nil {
		return fmt.Errorf("failed to set SQLite synchronous mode: %w", err)
	}

	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL;").Scan(&mode); err != nil {
		return fmt.Errorf("failed to enable SQLite WAL: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("failed to enable SQLite WAL: journal_mode=%q", mode)
	}
	return nil
}
