package v2db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInferDSN(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		backend BackendKind
	}{
		{name: "postgres", in: "postgres://user:pass@localhost/db", backend: BackendPostgres},
		{name: "postgresql", in: "postgresql://user:pass@localhost/db", backend: BackendPostgres},
		{name: "sqlite-url", in: "sqlite:///tmp/x.db", backend: BackendSQLite},
		{name: "sqlite-file", in: "./data/revaulter.db", backend: BackendSQLite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InferDSN(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.backend, got.Backend)
		})
	}
}

func TestInferDSNInvalidScheme(t *testing.T) {
	_, err := InferDSN("mysql://localhost/db")
	require.Error(t, err)
}

func TestSQLiteOpenEnablesWAL(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "revaulter.db")

	conn, parsed, err := Open(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.Equal(t, BackendSQLite, parsed.Backend)
	require.NotNil(t, conn.SQLite)

	var journalMode string
	err = conn.SQLite.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode)
	require.NoError(t, err)
	require.Equal(t, "wal", journalMode)

	var foreignKeys int
	err = conn.SQLite.QueryRowContext(ctx, "PRAGMA foreign_keys;").Scan(&foreignKeys)
	require.NoError(t, err)
	require.Equal(t, 1, foreignKeys)
}
