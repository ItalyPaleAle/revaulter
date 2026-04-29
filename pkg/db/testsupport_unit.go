//go:build unit

package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	postgresadapter "github.com/italypaleale/go-sql-utils/adapter/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func NewTestDatabaseForServerTests(t *testing.T) *DB {
	t.Helper()

	baseDSN := os.Getenv("TEST_DATABASE_DSN")
	if baseDSN != "" {
		return newTestPostgresDB(t, baseDSN)
	}

	h := sha256.Sum256([]byte(t.Name()))
	dbName := hex.EncodeToString(h[:12])

	conn, err := Open(t.Context(), "file:"+dbName+"?mode=memory")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close(t.Context())
	})

	return conn
}

// newTestPostgresDB creates a Postgres DB for testing with an isolated schema per test.
func newTestPostgresDB(t *testing.T, baseDSN string) *DB {
	t.Helper()

	h := sha256.Sum256([]byte(t.Name()))
	schemaName := "t" + hex.EncodeToString(h[:12])

	cfg, err := pgxpool.ParseConfig(baseDSN)
	require.NoError(t, err)

	// Create the schema using the base config (without search_path set)
	setupPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	_, err = setupPool.Exec(t.Context(), "CREATE SCHEMA IF NOT EXISTS "+schemaName)
	setupPool.Close()
	require.NoError(t, err)

	// Connect with search_path pointing to the new schema
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)

	conn := &DB{
		kind:         BackendPostgres,
		pgx:          pool,
		DatabaseConn: postgresadapter.AdaptPgxConn(pool),
	}

	t.Cleanup(func() {
		_ = conn.Close(t.Context())

		// We need to reconnect to the database using the base DSN (without search_path set)
		// Parse the configuration
		dropCfg, err := pgxpool.ParseConfig(baseDSN)
		if err != nil {
			return
		}

		// Connect to the database
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dropPool, err := pgxpool.NewWithConfig(ctx, dropCfg)
		if err != nil {
			return
		}
		defer dropPool.Close()

		// Drop the schema
		_, _ = dropPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	})

	return conn
}
