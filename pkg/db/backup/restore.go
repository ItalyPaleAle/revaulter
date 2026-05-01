package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/italypaleale/revaulter/pkg/db"
)

// Restore reads a backup produced by Backup and inserts all rows into conn
//
// The target database must already have its schema migrated to at least the version recorded in the backup (i.e. RunMigrations should be called before Restore)
// Restore returns an error if the backup was created with migrations not yet applied on the target
//
// Rows are inserted in FK-safe order inside a single transaction so that a failure leaves the database unchanged
func Restore(ctx context.Context, conn *db.DB, r io.Reader) error {
	bf, err := readBackup(r)
	if err != nil {
		return err
	}

	err = validateMigrations(ctx, conn, bf.Migrations)
	if err != nil {
		return err
	}

	specByName := make(map[string]tableSpec, len(backupTables))
	for _, spec := range backupTables {
		specByName[spec.name] = spec
	}

	_, err = db.ExecuteInTransaction(ctx, conn, 0, func(ctx context.Context, tx *db.DbTx) (struct{}, error) {
		for _, tb := range bf.Tables {
			spec, ok := specByName[tb.Name]
			if !ok {
				// Unknown table: skip gracefully (forward-compat: newer backup, older binary)
				continue
			}
			err := restoreTable(ctx, tx, conn.Kind(), spec, tb)
			if err != nil {
				return struct{}{}, fmt.Errorf("restoring table %q: %w", tb.Name, err)
			}
		}
		return struct{}{}, nil
	})
	return err
}

// readBackup reads and validates the magic header then decodes the CBOR payload
func readBackup(r io.Reader) (BackupFile, error) {
	var header [4]byte
	_, err := io.ReadFull(r, header[:])
	if err != nil {
		return BackupFile{}, fmt.Errorf("reading backup header: %w", err)
	}
	if header != magicHeader {
		return BackupFile{}, fmt.Errorf("not a valid backup file (bad magic header)")
	}

	var bf BackupFile
	dec := cbor.NewDecoder(r)
	err = dec.Decode(&bf)
	if err != nil {
		return BackupFile{}, fmt.Errorf("decoding backup: %w", err)
	}

	if bf.Version != formatVersion {
		return BackupFile{}, fmt.Errorf("unsupported backup format version %d (expected %d)", bf.Version, formatVersion)
	}

	return bf, nil
}

// validateMigrations checks that every migration recorded in the backup has already been applied to the target database
func validateMigrations(ctx context.Context, conn *db.DB, required []string) error {
	if len(required) == 0 {
		return nil
	}

	row := conn.QueryRow(ctx, `SELECT value FROM metadata WHERE key = 'migrations'`)
	var raw string
	err := row.Scan(&raw)
	if err != nil {
		if conn.IsNoRowsError(err) {
			return fmt.Errorf("target database has no migration metadata; run migrations before restoring")
		}
		return fmt.Errorf("reading target migration metadata: %w", err)
	}

	var applied []string
	err = json.Unmarshal([]byte(raw), &applied)
	if err != nil {
		return fmt.Errorf("parsing target migration metadata: %w", err)
	}

	appliedSet := make(map[string]bool, len(applied))
	for _, m := range applied {
		appliedSet[m] = true
	}

	for _, m := range required {
		if !appliedSet[m] {
			return fmt.Errorf("backup requires migration %q which has not been applied to the target database", m)
		}
	}

	return nil
}

// restoreTable inserts all rows from tb into the target table via tx
func restoreTable(ctx context.Context, tx *db.DbTx, kind db.BackendKind, spec tableSpec, tb TableBackup) error {
	if len(tb.Rows) == 0 {
		return nil
	}

	// Build a column spec index so we handle any column order in the backup
	colSpecByName := make(map[string]columnSpec, len(spec.columns))
	for _, c := range spec.columns {
		colSpecByName[c.name] = c
	}

	// Use the column list from the backup to honour its ordering and handle any extra/missing columns gracefully across schema versions
	query, buildArgs := buildInsert(spec.name, tb.Columns, colSpecByName, kind)

	for _, row := range tb.Rows {
		args, err := buildArgs(row)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
	}

	return nil
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
				case colKindJSONB:
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
