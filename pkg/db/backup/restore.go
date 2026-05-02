package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/italypaleale/go-sql-utils/adapter"

	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

// ErrTargetNotEmpty is returned by Restore when the target database already has data and Restore would otherwise overwrite it
// Callers can use errors.Is to detect this specific failure mode
var ErrTargetNotEmpty = errors.New("target database is not empty, refusing to overwrite: restore can only be performed on a fresh database")

// restoreTxTimeout caps the duration of the restore transaction
// On the SQL adapter the timeout applies to the whole transaction, so this needs to be generous enough for very large datasets
const restoreTxTimeout = time.Hour

// Restore reads a backup produced by Backup and inserts all rows into conn
// Migrations are applied to conn up to (and only up to) the source's schema level — any newer migrations bundled with the binary are intentionally left for the application to apply on its next startup
// Restore returns an error if the source schema level is newer than what the target binary can produce (meaning, the running binary is too old to safely restore the backup)
// Rows are then streamed and inserted in FK-safe order inside a single transaction, so a failure during row restore rolls back inserted rows.
// Note that migrations are applied before that transaction starts, so a restore failure after migrations may still leave schema changes and migration metadata updates in place.
func Restore(ctx context.Context, conn *db.DB, r io.Reader) error {
	var magic [4]byte
	_, err := io.ReadFull(r, magic[:])
	if err != nil {
		return fmt.Errorf("reading backup magic header: %w", err)
	}
	if magic != magicHeader {
		return errBadMagic
	}

	dec := decMode.NewDecoder(r)

	var hdr fileHeader
	err = dec.Decode(&hdr)
	if err != nil {
		return fmt.Errorf("decoding file header: %w", err)
	}
	if hdr.Version != formatVersion {
		return fmt.Errorf("unsupported backup format version %d (expected %d)", hdr.Version, formatVersion)
	}

	// Refuse to restore onto a database that already has data
	// We detect this by looking for the metadata table and checking whether any migration level has been recorded
	hasData, err := targetHasMigrations(ctx, conn)
	if err != nil {
		return fmt.Errorf("checking target database state: %w", err)
	}
	if hasData {
		return ErrTargetNotEmpty
	}

	// Bring the target database up to (and only up to) the source's schema level
	// Any migrations beyond that are intentionally left for the application to apply on its next startup
	// RunMigrationsUpTo errors out if this binary doesn't have enough bundled migrations to satisfy the source level
	err = db.RunMigrationsUpTo(ctx, conn, logging.LogFromContext(ctx), hdr.SchemaLevel)
	if err != nil {
		return fmt.Errorf("applying migrations to target database: %w", err)
	}

	specByName := make(map[string]tableSpec, len(backupTables))
	for _, spec := range backupTables {
		specByName[spec.name] = spec
	}

	_, err = db.ExecuteInTransaction(ctx, conn, restoreTxTimeout, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		for i := range hdr.TableCount {
			rErr := restoreTableBlock(ctx, tx, conn.Kind(), specByName, dec)
			if rErr != nil {
				return struct{}{}, fmt.Errorf("restoring table %d: %w", i, rErr)
			}
		}
		return struct{}{}, nil
	})
	return err
}

// restoreTableBlock reads one table block (header + rows + sentinel) from dec and inserts the rows into tx
//
// Unknown tables (e.g. a newer backup carrying a table that no longer exists in this binary) are read past but not inserted
func restoreTableBlock(ctx context.Context, tx *db.DbTx, kind db.BackendKind, specByName map[string]tableSpec, dec *cbor.Decoder) error {
	var tHdr tableHeader
	err := dec.Decode(&tHdr)
	if err != nil {
		return fmt.Errorf("decoding table header: %w", err)
	}

	spec, known := specByName[tHdr.Name]

	var (
		query     string
		buildArgs func(row []any) ([]any, error)
	)
	if known {
		colSpecByName := make(map[string]columnSpec, len(spec.columns))
		for _, c := range spec.columns {
			colSpecByName[c.name] = c
		}

		// Validate every column name from the backup stream against the known schema
		// Column names cannot be parameterized, so we must ensure they are all recognized identifiers before concatenating them into SQL
		for _, col := range tHdr.Columns {
			if _, ok := colSpecByName[col]; !ok {
				return fmt.Errorf("backup column %q is not a recognized column in table %q", col, tHdr.Name)
			}
		}

		query, buildArgs = buildInsert(spec.name, tHdr.Columns, colSpecByName, kind)
	}

	for {
		var row []any
		err = dec.Decode(&row)
		if err != nil {
			return fmt.Errorf("decoding row in table %q: %w", tHdr.Name, err)
		}
		// nil row is the end-of-table sentinel
		if row == nil {
			return nil
		}
		if !known {
			// Forward-compat: silently skip rows from unknown tables
			continue
		}

		args, err := buildArgs(row)
		if err != nil {
			return fmt.Errorf("building args for row in table %q: %w", tHdr.Name, err)
		}
		_, err = tx.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("inserting row into %q: %w", tHdr.Name, err)
		}
	}
}

// buildInsert constructs an INSERT statement and returns a function that maps a backup row into the argument slice for that statement
//
// For Postgres, uuid and jsonb columns get explicit type casts (::uuid, ::jsonb)
func buildInsert(
	table string,
	columns []string,
	colSpecByName map[string]columnSpec,
	kind db.BackendKind,
) (query string, buildArgs func(row []any) ([]any, error)) {
	placeholders := make([]string, len(columns))
	for i, name := range columns {
		ph := placeholder(i+1, kind)
		if kind == db.BackendPostgres {
			spec, ok := colSpecByName[name]
			if ok {
				switch spec.kind {
				case colKindUUID:
					ph = fmt.Sprintf("$%d::uuid", i+1)
				case colKindJSON:
					ph = fmt.Sprintf("$%d::jsonb", i+1)
				}
			}
		}
		placeholders[i] = ph
	}

	query = fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	buildArgs = func(row []any) ([]any, error) {
		if len(row) != len(columns) {
			return nil, fmt.Errorf("row has %d values but table %s has %d columns", len(row), table, len(columns))
		}
		args := make([]any, len(row))
		for i, v := range row {
			args[i] = coerceForInsert(v, colSpecByName[columns[i]], kind)
		}
		return args, nil
	}

	return query, buildArgs
}

// placeholder returns the parameter placeholder for a 1-based index
func placeholder(n int, kind db.BackendKind) string {
	if kind == db.BackendPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// targetHasMigrations reports whether conn already records an applied migration
// The check passes (returns false) if either the metadata table is absent, or it is present but has no migrations row, or the recorded migration level is 0
// Any other recorded level means the target has been migrated and likely contains data, so a restore would overwrite it
func targetHasMigrations(ctx context.Context, conn *db.DB) (bool, error) {
	exists, err := metadataTableExists(ctx, conn, conn.Kind())
	if err != nil {
		return false, fmt.Errorf("looking up metadata table: %w", err)
	}
	if !exists {
		return false, nil
	}

	level, err := readSchemaLevel(ctx, conn)
	if err != nil {
		return false, err
	}

	return level > 0, nil
}

// metadataTableExists reports whether the metadata table is present in the connected schema
func metadataTableExists(ctx context.Context, conn adapter.Querier, kind db.BackendKind) (bool, error) {
	var (
		query string
		args  []any
	)
	switch kind {
	case db.BackendSQLite:
		query = `SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`
		args = []any{metadataTableName}
	case db.BackendPostgres:
		query = `SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`
		args = []any{metadataTableName}
	default:
		return false, fmt.Errorf("unsupported backend kind %q", kind)
	}

	row := conn.QueryRow(ctx, query, args...)
	var dummy int
	err := row.Scan(&dummy)
	if conn.IsNoRowsError(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

// coerceForInsert converts a normalised backup value to the appropriate Go type for the target database column, handling cross-engine boolean differences
func coerceForInsert(v any, spec columnSpec, kind db.BackendKind) any {
	if v == nil {
		return nil
	}

	switch kind {
	case db.BackendSQLite:
		if spec.kind == colKindBool {
			b, ok := v.(bool)
			if ok {
				if b {
					return int64(1)
				}
				return int64(0)
			}
		}

	case db.BackendPostgres:
		if spec.kind == colKindBool {
			switch val := v.(type) {
			case bool:
				return val
			case int64:
				return val != 0
			}
		}
	}

	return v
}
