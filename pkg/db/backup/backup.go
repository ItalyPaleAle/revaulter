//go:generate go run ./gen/

// Package backup provides functions for exporting and importing the application database in a backend-agnostic format, suitable for long-term storage and cross-database-engine migration (e.g. restoring a SQLite dump into Postgres)
//
// The backup format uses CBOR (RFC 8949) for compact binary encoding
// It contains only data — no schema DDL — along with the source schema migration level so the target database can be brought to a compatible schema before the data is restored
package backup

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/italypaleale/go-sql-utils/adapter"
)

// Backup streams a CBOR-encoded snapshot of all persistent tables in conn to w
// The backup contains data only (no DDL) and embeds the migration level of the source database so the restore process can verify schema compatibility
// Rows are streamed to w one at a time without buffering the entire database in memory
// Backup does not open a transaction, so concurrent writes to conn during backup may produce a slightly inconsistent snapshot between tables
// Callers that need a strictly consistent snapshot should arrange exclusive access (e.g. by halting writers) for the duration of the call
func Backup(ctx context.Context, conn adapter.Querier, w io.Writer) error {
	level, err := readSchemaLevel(ctx, conn)
	if err != nil {
		return fmt.Errorf("reading source schema level: %w", err)
	}

	_, err = w.Write(magicHeader[:])
	if err != nil {
		return fmt.Errorf("writing backup header: %w", err)
	}

	enc := encMode.NewEncoder(w)

	err = enc.Encode(fileHeader{
		Version:     formatVersion,
		CreatedAt:   time.Now().Unix(),
		SchemaLevel: level,
		TableCount:  len(backupTables),
	})
	if err != nil {
		return fmt.Errorf("encoding file header: %w", err)
	}

	for _, spec := range backupTables {
		err = dumpTable(ctx, conn, spec, enc)
		if err != nil {
			return fmt.Errorf("dumping table %q: %w", spec.name, err)
		}
	}

	return nil
}

// dumpTable writes a single table block (header + rows + end-of-table sentinel) to enc
func dumpTable(ctx context.Context, conn adapter.Querier, spec tableSpec, enc *cbor.Encoder) error {
	colNames := spec.columnNames()

	err := enc.Encode(tableHeader{
		Name:    spec.name,
		Columns: colNames,
	})
	if err != nil {
		return fmt.Errorf("encoding table header: %w", err)
	}

	query := "SELECT " + strings.Join(colNames, ", ") + " FROM " + spec.name
	rows, err := conn.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("querying rows: %w", err)
	}
	defer rows.Close()

	scanDest := make([]any, len(spec.columns))
	scanPtrs := make([]any, len(spec.columns))
	for i := range scanDest {
		scanPtrs[i] = &scanDest[i]
	}

	for rows.Next() {
		err = rows.Scan(scanPtrs...)
		if err != nil {
			return fmt.Errorf("scanning row: %w", err)
		}

		row := make([]any, len(spec.columns))
		for i, v := range scanDest {
			row[i] = normalizeValue(v, spec.columns[i].kind)
		}

		err = enc.Encode(row)
		if err != nil {
			return fmt.Errorf("encoding row: %w", err)
		}
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating rows: %w", err)
	}

	// End-of-table sentinel: a CBOR null
	// On decode, this materialises as a nil []any
	err = enc.Encode(nil)
	if err != nil {
		return fmt.Errorf("encoding end-of-table sentinel: %w", err)
	}

	return nil
}
