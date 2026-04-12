//go:build unit

package v2db

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func NewTestDatabaseForServerTests(t *testing.T) *DB {
	t.Helper()

	h := sha256.Sum256([]byte(t.Name()))
	dbName := hex.EncodeToString(h[:12])

	conn, err := Open(t.Context(), "file:"+dbName+"?mode=memory")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close(t.Context())
	})

	return conn
}
