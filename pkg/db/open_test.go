package db

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestDatabase(t *testing.T) *DB {
	baseDSN := os.Getenv("TEST_DATABASE_DSN")
	if baseDSN != "" {
		return newTestPostgresDB(t, baseDSN)
	}

	// Use a unique name for the database to use different ones
	h := sha256.Sum256([]byte(t.Name()))
	dbName := hex.EncodeToString(h[:12])

	// Connect to an in-memory database
	conn, err := Open(t.Context(), "file:"+dbName+"?mode=memory")
	require.NoError(t, err)

	// Disconnect when done
	t.Cleanup(func() { _ = conn.Close(t.Context()) })

	return conn
}
