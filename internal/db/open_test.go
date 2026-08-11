package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// runDBTest runs fn as two subtests:
// - Against SQLite
// - Against Postgres (only when TEST_POSTGRES_DSN is set)
func runDBTest(t *testing.T, fn func(t *testing.T, conn *DB)) {
	t.Helper()

	t.Run("SQLite", func(t *testing.T) {
		fn(t, newSQLiteTestDB(t))
	})

	t.Run("Postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("TEST_POSTGRES_DSN not set; skipping Postgres test")
		}
		fn(t, newPostgresTestDB(t, dsn))
	})
}

// newSQLiteTestDB returns a fresh in-memory SQLite DB whose name is unique to this test.
func newSQLiteTestDB(t *testing.T) *DB {
	t.Helper()

	h := sha256.Sum256([]byte(t.Name()))
	dbName := hex.EncodeToString(h[:12])

	conn, err := Open(t.Context(), "file:"+dbName+"?mode=memory")
	require.NoError(t, err)

	t.Cleanup(func() { _ = conn.Close(t.Context()) })

	return conn
}

// newPostgresTestDB connects to the Postgres instance at baseDSN in an isolated schema unique to this test.
func newPostgresTestDB(t *testing.T, baseDSN string) *DB {
	t.Helper()

	h := sha256.Sum256([]byte(t.Name()))
	schemaName := "t" + hex.EncodeToString(h[:12])

	setupCfg, err := pgxpool.ParseConfig(baseDSN)
	require.NoError(t, err)
	setupPool, err := pgxpool.NewWithConfig(t.Context(), setupCfg)
	require.NoError(t, err)
	_, err = setupPool.Exec(t.Context(), "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	require.NoError(t, err)
	_, err = setupPool.Exec(t.Context(), "CREATE SCHEMA "+schemaName)
	setupPool.Close()
	require.NoError(t, err)

	sep := "?"
	if strings.Contains(baseDSN, "?") {
		sep = "&"
	}
	conn, err := Open(t.Context(), baseDSN+sep+"search_path="+schemaName)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close(t.Context())

		// Use a fresh context — t.Context() may already be done by cleanup time
		cleanCfg, err := pgxpool.ParseConfig(baseDSN)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanPool, err := pgxpool.NewWithConfig(ctx, cleanCfg)
		if err != nil {
			return
		}
		defer cleanPool.Close()
		_, _ = cleanPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	})

	return conn
}
