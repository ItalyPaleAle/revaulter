//go:generate go run ./gen/

// Package backup provides functions for exporting and importing the application
// database in a backend-agnostic format, suitable for long-term storage and
// cross-database-engine migration (e.g. restoring a SQLite dump into Postgres).
//
// The backup format uses CBOR (RFC 8949) for compact binary encoding. It contains
// only data — no schema DDL — along with the list of applied migrations so that the
// target database can be migrated to the exact same version before the restore.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/italypaleale/revaulter/pkg/db"
)

// formatVersion is the version of the backup file format.
// Increment this if the structure of BackupFile or Row changes in a breaking way.
const formatVersion uint8 = 1

// magicHeader is prepended to every backup file to identify it.
// "RVBK" = ReVaulter BacKup
var magicHeader = [4]byte{'R', 'V', 'B', 'K'}

// BackupFile is the top-level structure serialised into the backup file.
type BackupFile struct {
	// Version is the backup format version.
	Version uint8 `cbor:"v"`
	// CreatedAt is the Unix timestamp when the backup was created.
	CreatedAt int64 `cbor:"ca"`
	// Migrations is the ordered list of migration names that had been applied
	// to the source database at backup time. On restore this is used to bring
	// the target database to the same schema version before inserting data.
	Migrations []string `cbor:"mg"`
	// Tables contains the exported table data in FK-safe order.
	Tables []TableBackup `cbor:"tb"`
}

// TableBackup holds the exported rows for a single table.
type TableBackup struct {
	// Name is the table name.
	Name string `cbor:"n"`
	// Columns is the ordered list of column names. Each element of Rows
	// corresponds to this column list.
	Columns []string `cbor:"c"`
	// Rows contains the data rows. Each inner slice is parallel to Columns.
	// Values are one of: nil, bool, int64, float64, string.
	Rows [][]any `cbor:"r"`
}

// Backup reads all persistent tables from db and writes a CBOR-encoded backup to w.
//
// The backup contains only data (no DDL). The migration version of the source
// database is embedded so the restore process can verify schema compatibility.
func Backup(ctx context.Context, conn *db.DB, w io.Writer) error {
	migrations, err := readMigrations(ctx, conn)
	if err != nil {
		return fmt.Errorf("reading migration metadata: %w", err)
	}

	bf := BackupFile{
		Version:    formatVersion,
		CreatedAt:  time.Now().Unix(),
		Migrations: migrations,
		Tables:     make([]TableBackup, 0, len(backupTables)),
	}

	for _, spec := range backupTables {
		tb, err := dumpTable(ctx, conn, spec)
		if err != nil {
			return fmt.Errorf("dumping table %q: %w", spec.name, err)
		}
		bf.Tables = append(bf.Tables, tb)
	}

	// Write magic header then CBOR payload.
	if _, err := w.Write(magicHeader[:]); err != nil {
		return fmt.Errorf("writing backup header: %w", err)
	}

	enc := cbor.NewEncoder(w)
	if err := enc.Encode(bf); err != nil {
		return fmt.Errorf("encoding backup: %w", err)
	}

	return nil
}

// readMigrations queries the metadata table and returns the list of applied
// migration names stored under the "migrations" key.
func readMigrations(ctx context.Context, conn *db.DB) ([]string, error) {
	row := conn.QueryRow(ctx, `SELECT value FROM metadata WHERE key = 'migrations'`)

	var raw string
	if err := row.Scan(&raw); err != nil {
		if conn.IsNoRowsError(err) {
			return nil, nil
		}
		return nil, err
	}

	var migrations []string
	if err := json.Unmarshal([]byte(raw), &migrations); err != nil {
		return nil, fmt.Errorf("parsing migrations JSON: %w", err)
	}
	return migrations, nil
}

// dumpTable runs a SELECT over all tracked columns of spec.name and returns
// a TableBackup with normalised, CBOR-safe row data.
func dumpTable(ctx context.Context, conn *db.DB, spec tableSpec) (TableBackup, error) {
	colNames := spec.columnNames()
	query := "SELECT " + strings.Join(colNames, ", ") + " FROM " + spec.name

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return TableBackup{}, err
	}
	defer rows.Close()

	// Pre-build a reusable scan-destination slice.
	scanDest := make([]any, len(spec.columns))
	scanPtrs := make([]any, len(spec.columns))
	for i := range scanDest {
		scanPtrs[i] = &scanDest[i]
	}

	tb := TableBackup{
		Name:    spec.name,
		Columns: colNames,
	}

	for rows.Next() {
		if err := rows.Scan(scanPtrs...); err != nil {
			return TableBackup{}, fmt.Errorf("scanning row: %w", err)
		}

		row := make([]any, len(spec.columns))
		for i, v := range scanDest {
			row[i] = normalizeValue(v, spec.columns[i].kind)
		}
		tb.Rows = append(tb.Rows, row)
	}

	return tb, rows.Err()
}

// normalizeValue converts a raw value scanned from the database driver into one
// of the portable types stored in the backup: nil, bool, int64, float64, string.
//
// The colKind hint resolves ambiguity where the same Go type carries different
// semantic meaning (e.g. SQLite INTEGER used for both int64 and boolean columns).
func normalizeValue(v any, kind columnKind) any {
	switch val := v.(type) {
	case nil:
		return nil

	case bool:
		return val

	case int64:
		if kind == colKindBool {
			return val != 0
		}
		return val

	case int32:
		if kind == colKindBool {
			return val != 0
		}
		return int64(val)

	case int16:
		return int64(val)

	case float32:
		return float64(val)

	case float64:
		return val

	case string:
		return val

	case []byte:
		// Postgres JSONB and some text types come back as []byte.
		return string(val)

	case [16]byte:
		// pgx v5 returns raw UUID bytes for uuid columns.
		return uuid.UUID(val).String()
	}

	// Fallback: unknown driver-specific type — stringify it. This should not
	// happen for the known columns but avoids silent data loss.
	return fmt.Sprintf("%v", v)
}
