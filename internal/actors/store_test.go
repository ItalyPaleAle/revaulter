package actors

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/internal/config"
)

func TestResolveStore(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		databaseDSN string
		francisDSN  string
		wantKind    storeKind
		wantDSN     string
	}{
		{
			name:        "sqlite file gets a sibling file",
			databaseDSN: filepath.Join(dir, "revaulter.db"),
			wantKind:    storeSQLite,
			wantDSN:     filepath.Join(dir, "revaulter.francis.db"),
		},
		{
			name:        "sqlite file URL with parameters gets a sibling file",
			databaseDSN: "file:" + filepath.Join(dir, "data.sqlite") + "?_pragma=busy_timeout(5000)",
			wantKind:    storeSQLite,
			wantDSN:     filepath.Join(dir, "data.francis.db"),
		},
		{
			name:        "sqlite file without extension gets a sibling file",
			databaseDSN: filepath.Join(dir, "revaulter"),
			wantKind:    storeSQLite,
			wantDSN:     filepath.Join(dir, "revaulter.francis.db"),
		},
		{
			name:        "in-memory sqlite uses the memory store",
			databaseDSN: ":memory:",
			wantKind:    storeMemory,
		},
		{
			name:        "in-memory sqlite with mode=memory uses the memory store",
			databaseDSN: "file:test?mode=memory",
			wantKind:    storeMemory,
		},
		{
			name:        "postgres uses the same database",
			databaseDSN: "postgres://localhost:5432/revaulter",
			wantKind:    storePostgres,
			wantDSN:     "postgres://localhost:5432/revaulter",
		},
		{
			name:        "explicit sqlite DSN is used as-is",
			databaseDSN: "postgres://localhost:5432/revaulter",
			francisDSN:  filepath.Join(dir, "elsewhere.db"),
			wantKind:    storeSQLite,
			wantDSN:     filepath.Join(dir, "elsewhere.db"),
		},
		{
			name:        "explicit postgres DSN is used as-is",
			databaseDSN: filepath.Join(dir, "revaulter.db"),
			francisDSN:  "postgresql://db:5432/francis",
			wantKind:    storePostgres,
			wantDSN:     "postgresql://db:5432/francis",
		},
		{
			name:        "explicit in-memory DSN uses the memory store",
			databaseDSN: filepath.Join(dir, "revaulter.db"),
			francisDSN:  ":memory:",
			wantKind:    storeMemory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				DatabaseDSN:        tt.databaseDSN,
				FrancisDatabaseDSN: tt.francisDSN,
			}

			store, err := resolveStore(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantKind, store.kind)
			assert.Equal(t, tt.wantDSN, store.dsn)
		})
	}

	t.Run("fails without a connection string", func(t *testing.T) {
		_, err := resolveStore(&config.Config{})
		require.Error(t, err)
		require.ErrorContains(t, err, "connection string for the Francis database is empty")
	})
}
