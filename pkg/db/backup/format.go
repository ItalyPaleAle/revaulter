package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/italypaleale/go-sql-utils/adapter"
)

// formatVersion is the version of the backup file format
// Increment this if the structure of the file format or row encoding changes in a breaking way
const formatVersion uint8 = 1

// magicHeader is prepended to every backup file to identify it
// "RVBK" = ReVaulter BacKup
var magicHeader = [4]byte{'R', 'V', 'B', 'K'}

// metadataTableName / metadataKeyMigrations match the convention used by go-sql-utils migrations
// They identify the row that stores the schema migration level
const (
	metadataTableName     = "metadata"
	metadataKeyMigrations = "migrations"
)

// fileHeader is the first CBOR object after the magic bytes
//
// It carries top-level backup metadata
// SchemaLevel is the migration level (count of applied migrations) of the source database
// TableCount is the number of table blocks that follow
type fileHeader struct {
	Version     uint8 `cbor:"v"`
	CreatedAt   int64 `cbor:"ca"`
	SchemaLevel int   `cbor:"sl"`
	TableCount  int   `cbor:"tc"`
}

// tableHeader precedes each table block
//
// The table block layout is:
//
//	[tableHeader]
//	zero or more [row: CBOR array of values]
//	[CBOR null] (end-of-table sentinel)
type tableHeader struct {
	Name    string   `cbor:"n"`
	Columns []string `cbor:"c"`
}

// CBOR encoding/decoding modes used throughout the package
//
// The decoder uses IntDecConvertSignedOrFail so positive CBOR integers come back as int64 instead of uint64
// SQL drivers (database/sql, pgx) accept int64 but not uint64
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(fmt.Errorf("backup: setting up CBOR encoder: %w", err))
	}

	decMode, err = cbor.DecOptions{
		IntDec: cbor.IntDecConvertSignedOrFail,
	}.DecMode()
	if err != nil {
		panic(fmt.Errorf("backup: setting up CBOR decoder: %w", err))
	}
}

// readSchemaLevel returns the migration level recorded in the metadata table
// Returns 0 if no migrations row exists yet (e.g. the schema has not been migrated)
func readSchemaLevel(ctx context.Context, conn adapter.Querier) (int, error) {
	row := conn.QueryRow(ctx, `SELECT value FROM `+metadataTableName+` WHERE key = '`+metadataKeyMigrations+`'`)

	var raw string
	err := row.Scan(&raw)
	if err != nil {
		if conn.IsNoRowsError(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading migration level from metadata: %w", err)
	}

	level, err := strconv.Atoi(raw)
	if err != nil || level < 0 {
		return 0, fmt.Errorf("invalid migration level %q in metadata table", raw)
	}
	return level, nil
}

// normalizeValue converts a raw value scanned from the database driver into one of the portable types stored in the backup: nil, bool, int64, float64, string
//
// The colKind hint resolves ambiguity where the same Go type carries different semantic meaning (e.g. SQLite INTEGER used for both int64 and boolean columns)
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
		// Postgres JSONB and some text types come back as []byte
		return string(val)

	case [16]byte:
		// pgx v5 returns raw UUID bytes for uuid columns
		return uuid.UUID(val).String()

	case map[string]any, []any:
		// pgx v5 returns parsed JSON (object or array) for jsonb columns when scanning into *interface{}
		// Re-serialise to a canonical JSON string so the backup is portable to backends that store JSON as text
		b, err := json.Marshal(val)
		if err == nil {
			return string(b)
		}
		// Fall through on marshal failure
	}

	// Fallback: unknown driver-specific type — stringify it
	// This should not happen for the known columns but avoids silent data loss
	return fmt.Sprintf("%v", v)
}

// errBadMagic is returned when the magic header on a backup stream does not match
var errBadMagic = errors.New("not a valid backup file (bad magic header)")
