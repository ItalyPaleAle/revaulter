//go:build unit

package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/db"
)

// fixtureBackup is the in-memory representation of a backup file used by the round-trip tests
type fixtureBackup struct {
	SchemaLevel int
	Tables      []fixtureTable
}

type fixtureTable struct {
	Name    string
	Columns []string
	Rows    [][]any
}

const (
	fxUserAID   = "user-A"
	fxUserBID   = "user-B"
	fxCredAID   = "cred-A"
	fxRequestID = "req-state-1"
	fxSigningID = "sk-1"
	fxAuditID1  = "11111111-1111-4111-8111-111111111111"
	fxAuditID2  = "22222222-2222-4222-8222-222222222222"
)

// canonicalFixture builds the canonical fixture used by the round-trip tests
//
// The values are chosen to exercise every supported columnKind: text, bool, uuid, json (jsonb on Postgres), int64, and nullable columns
//
// SchemaLevel must match the count of embedded migrations
// If a new migration is added under pkg/db/migrations, bump this value
func canonicalFixture() fixtureBackup {
	const ts = int64(1700000000)

	return fixtureBackup{
		SchemaLevel: 1,
		Tables: []fixtureTable{
			tableFixture("v2_audit_events", [][]any{
				{fxAuditID1, ts, "auth.login.finish", "success", "session", fxUserAID, fxUserAID, nil, nil, fxRequestID, "http-1", "127.0.0.1", "ua/1.0", `{"flow":"webauthn"}`},
				{fxAuditID2, ts + 1, "auth.logout", "success", "session", fxUserBID, nil, nil, nil, nil, nil, nil, nil, `{}`},
			}),
			tableFixture("v2_users", [][]any{
				{fxUserAID, "Alice", "active", "wa-A", "rk-A", "ecdh-A", "mlkem-A", "es384-A", "mldsa-A", "sig-es-A", "sig-mldsa-A", int64(1), "10.0.0.0/8", true, ts, ts},
				{fxUserBID, "Bob", "active", "wa-B", "rk-B", "", "", "", "", "", "", int64(2), "", false, ts - 100, ts - 50},
			}),
			tableFixture("v2_published_signing_keys", [][]any{
				{fxSigningID, fxUserAID, "ES384", "label-1", `{"jwk":1}`, "PEMDATA", true, "pub-payload", "pub-sig-es", "pub-sig-mldsa", ts, ts},
			}),
			tableFixture("v2_requests", [][]any{
				{fxRequestID, "pending", "sign", fxUserAID, "label-2", "ES384", "192.168.1.1", "test note", ts, ts + 600, ts, "encReq", "encRes"},
			}),
			tableFixture("v2_user_credentials", [][]any{
				{fxCredAID, fxUserAID, "raw-cred-id", "Cred-A", "pubkey-blob", int64(7), "wpk", "wak", "att-payload", "att-sig-es", "att-sig-mldsa", int64(1), ts, ts + 10},
			}),
		},
	}
}

// tableFixture builds a fixtureTable, validating that each row has one value per column in the spec
func tableFixture(name string, rows [][]any) fixtureTable {
	var spec tableSpec
	for _, s := range backupTables {
		if s.name == name {
			spec = s
			break
		}
	}
	if spec.name == "" {
		panic("unknown table: " + name)
	}

	cols := spec.columnNames()
	for i, row := range rows {
		if len(row) != len(cols) {
			panic(fmt.Sprintf("fixture row %d for table %q has %d values; expected %d", i, name, len(row), len(cols)))
		}
	}

	return fixtureTable{
		Name:    name,
		Columns: cols,
		Rows:    rows,
	}
}

// writeFixture serialises fb to w using the streaming backup format
func writeFixture(w io.Writer, fb fixtureBackup) error {
	_, err := w.Write(magicHeader[:])
	if err != nil {
		return err
	}

	enc := encMode.NewEncoder(w)

	err = enc.Encode(fileHeader{
		Version:     formatVersion,
		CreatedAt:   1700000000,
		SchemaLevel: fb.SchemaLevel,
		TableCount:  len(fb.Tables),
	})
	if err != nil {
		return err
	}

	for _, t := range fb.Tables {
		err = enc.Encode(tableHeader{
			Name:    t.Name,
			Columns: t.Columns,
		})
		if err != nil {
			return err
		}

		for _, row := range t.Rows {
			err = enc.Encode(row)
			if err != nil {
				return err
			}
		}

		// End-of-table sentinel
		err = enc.Encode(nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// readFixture decodes a streaming backup blob into the in-memory fixture form
// CreatedAt is intentionally not captured: it is volatile (time.Now) and not part of the data round-trip
func readFixture(t *testing.T, r io.Reader) fixtureBackup {
	t.Helper()

	var magic [4]byte
	_, err := io.ReadFull(r, magic[:])
	require.NoError(t, err)
	require.Equal(t, magicHeader, magic, "magic header mismatch")

	dec := decMode.NewDecoder(r)

	var hdr fileHeader
	require.NoError(t, dec.Decode(&hdr))
	require.Equal(t, formatVersion, hdr.Version)

	fb := fixtureBackup{
		SchemaLevel: hdr.SchemaLevel,
		Tables:      make([]fixtureTable, 0, hdr.TableCount),
	}

	for range hdr.TableCount {
		var tHdr tableHeader
		require.NoError(t, dec.Decode(&tHdr))

		var rows [][]any
		for {
			var row []any
			require.NoError(t, dec.Decode(&row))
			if row == nil {
				break
			}
			rows = append(rows, row)
		}

		fb.Tables = append(fb.Tables, fixtureTable{
			Name:    tHdr.Name,
			Columns: tHdr.Columns,
			Rows:    rows,
		})
	}
	return fb
}

// --- round-trip tests ---

func TestBackupRestoreRoundTrip_SQLite(t *testing.T) {
	conn := newSQLiteTestDB(t)
	runRoundTrip(t, conn)
}

func TestBackupRestoreRoundTrip_Postgres(t *testing.T) {
	conn := newPostgresTestDB(t)
	runRoundTrip(t, conn)
}

// TestRestore_RefusesNonEmptyTarget verifies Restore aborts with ErrTargetNotEmpty when the target already has migration metadata
func TestRestore_RefusesNonEmptyTarget_SQLite(t *testing.T) {
	runRefusesNonEmptyTarget(t, newSQLiteTestDB(t))
}

func TestRestore_RefusesNonEmptyTarget_Postgres(t *testing.T) {
	runRefusesNonEmptyTarget(t, newPostgresTestDB(t))
}

func runRefusesNonEmptyTarget(t *testing.T, conn *db.DB) {
	t.Helper()

	// Migrate the target so metadata has a non-zero level
	require.NoError(t, db.RunMigrations(t.Context(), conn, nil))

	// Encode a fixture and try to restore — should refuse
	var fixtureBytes bytes.Buffer
	require.NoError(t, writeFixture(&fixtureBytes, canonicalFixture()))

	err := Restore(t.Context(), conn, &fixtureBytes)
	require.ErrorIs(t, err, ErrTargetNotEmpty)
}

func runRoundTrip(t *testing.T, conn *db.DB) {
	t.Helper()

	fixture := canonicalFixture()

	// Encode the fixture to a backup blob
	var fixtureBytes bytes.Buffer
	require.NoError(t, writeFixture(&fixtureBytes, fixture))

	// Restore into the fresh DB
	// Restore applies migrations itself; we deliberately do not call db.RunMigrations beforehand
	require.NoError(t, Restore(t.Context(), conn, &fixtureBytes))

	// Sanity check: each table has the expected row count
	for _, table := range fixture.Tables {
		var got int64
		err := conn.QueryRow(t.Context(), "SELECT COUNT(*) FROM "+table.Name).Scan(&got)
		require.NoError(t, err, "counting rows in %s", table.Name)
		require.Equal(t, int64(len(table.Rows)), got, "row count for %s", table.Name)
	}

	// Re-export and compare
	var actualBytes bytes.Buffer
	require.NoError(t, Backup(t.Context(), conn.DatabaseConn, &actualBytes))

	actual := readFixture(t, &actualBytes)

	require.Equal(t, fixture.SchemaLevel, actual.SchemaLevel, "schema level mismatch")
	require.Len(t, fixture.Tables, len(actual.Tables), "table count")

	expByName := indexFixtureTables(fixture.Tables)
	actByName := indexFixtureTables(actual.Tables)

	for name, exp := range expByName {
		act, ok := actByName[name]
		require.True(t, ok, "table %q missing from re-exported backup", name)
		require.Equal(t, exp.Columns, act.Columns, "columns differ for %q", name)
		require.Equal(t, sortRows(exp.Rows), sortRows(act.Rows), "rows differ for %q", name)
	}
}

func indexFixtureTables(tables []fixtureTable) map[string]fixtureTable {
	out := make(map[string]fixtureTable, len(tables))
	for _, t := range tables {
		out[t.Name] = t
	}
	return out
}

// sortRows returns a copy of rows sorted by the canonical key (first column, stringified)
//
// Row ordering from a SELECT without ORDER BY is implementation-defined, so the test must not rely on it
func sortRows(rows [][]any) [][]any {
	out := make([][]any, len(rows))
	copy(out, rows)
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprintf("%v", out[i][0]) < fmt.Sprintf("%v", out[j][0])
	})
	return out
}

// --- error-path tests ---

func TestRestore_SchemaLevelTooNew(t *testing.T) {
	conn := newSQLiteTestDB(t)

	// Craft a backup that claims a SchemaLevel beyond what the bundled migrations can satisfy
	// Restore must return an error ("binary too old") before touching any rows
	var buf bytes.Buffer
	err := writeFixture(&buf, fixtureBackup{
		SchemaLevel: 9999,
		Tables:      nil,
	})
	require.NoError(t, err)

	restoreErr := Restore(t.Context(), conn, &buf)
	require.Error(t, restoreErr)
	require.ErrorContains(t, restoreErr, "9999")
}

func TestRestore_UnrecognizedColumnRejected(t *testing.T) {
	conn := newSQLiteTestDB(t)

	// Craft a backup with a known table but a column name that doesn't exist in the schema
	// Restore must reject it before executing any SQL, preventing identifier injection
	var buf bytes.Buffer
	err := writeFixture(&buf, fixtureBackup{
		SchemaLevel: 1,
		Tables: []fixtureTable{
			{
				Name:    "v2_users",
				Columns: []string{"id; DROP TABLE v2_users; --"},
				Rows:    [][]any{{"val"}},
			},
		},
	})
	require.NoError(t, err)

	restoreErr := Restore(t.Context(), conn, &buf)
	require.Error(t, restoreErr)
	require.ErrorContains(t, restoreErr, "not a recognized column")
}

// --- DB setup ---

func newSQLiteTestDB(t *testing.T) *db.DB {
	t.Helper()

	h := sha256.Sum256([]byte(t.Name()))
	dbName := hex.EncodeToString(h[:12])
	conn, err := db.Open(t.Context(), "file:"+dbName+"?mode=memory")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(t.Context()) })
	return conn
}

// newPostgresTestDB connects to the Postgres instance pointed at by TEST_POSTGRES_DSN, in an isolated schema unique to this test
//
// Skips the test if TEST_POSTGRES_DSN is unset
func newPostgresTestDB(t *testing.T) *db.DB {
	t.Helper()

	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping Postgres test")
	}

	h := sha256.Sum256([]byte(t.Name()))
	schemaName := "t" + hex.EncodeToString(h[:12])

	// Create a fresh schema using a direct pgx pool (no search_path override)
	setupCfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	setupPool, err := pgxpool.NewWithConfig(t.Context(), setupCfg)
	require.NoError(t, err)
	_, err = setupPool.Exec(t.Context(), "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	require.NoError(t, err)
	_, err = setupPool.Exec(t.Context(), "CREATE SCHEMA "+schemaName)
	setupPool.Close()
	require.NoError(t, err)

	// Append search_path to the DSN so pgx pins all sessions to our isolated schema
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	conn, err := db.Open(t.Context(), dsn+sep+"search_path="+schemaName)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close(t.Context())

		// Drop the schema using a fresh context — t.Context() may already be done by cleanup time
		cleanCfg, err := pgxpool.ParseConfig(dsn)
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
