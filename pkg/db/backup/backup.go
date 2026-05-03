//go:generate go run ./gen/

// Package backup provides functions for exporting and importing the application database in a backend-agnostic format, suitable for long-term storage and cross-database-engine migration (e.g. restoring a SQLite dump into Postgres)
//
// The backup format uses CBOR (RFC 8949) for compact binary encoding
// It contains only data — no schema DDL — along with the source schema migration level so the target database can be brought to a compatible schema before the data is restored
package backup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/italypaleale/go-sql-utils/adapter"

	transactions "github.com/italypaleale/go-sql-utils/transactions/adapter"
)

// backupTxTimeout caps the duration of the backup transaction
// On the SQL adapter the timeout applies to the whole transaction, so this needs to be generous enough for very large datasets
const backupTxTimeout = time.Hour

// Backup streams a CBOR-encoded snapshot of all persistent tables in conn to w
// The backup contains data only (no DDL) and embeds the migration level of the source database so the restore process can verify schema compatibility
// Rows are streamed to w one at a time without buffering the entire database in memory
// All reads happen inside a single transaction so the dump represents a consistent snapshot across tables
func Backup(ctx context.Context, conn adapter.DatabaseConn, w io.Writer) error {
	_, err := transactions.ExecuteInTransaction(
		ctx,
		slog.Default(),
		conn,
		backupTxTimeout,
		func(ctx context.Context, tx adapter.Querier) (struct{}, error) {
			return struct{}{}, runBackup(ctx, tx, w)
		},
	)
	return err
}

// runBackup performs the actual dump using the supplied transaction
func runBackup(ctx context.Context, tx adapter.Querier, w io.Writer) error {
	level, err := readSchemaLevel(ctx, tx)
	if err != nil {
		return fmt.Errorf("reading source schema level: %w", err)
	}

	// Write the magic header
	_, err = w.Write(magicHeader[:])
	if err != nil {
		return fmt.Errorf("writing backup header: %w", err)
	}

	// Compute the checksum as we write the backup file
	h := sha256.New()
	enc := encMode.NewEncoder(io.MultiWriter(w, h))

	// Add the header
	err = enc.Encode(fileHeader{
		Version:     formatVersion,
		CreatedAt:   time.Now().Unix(),
		SchemaLevel: level,
		TableCount:  len(backupTables),
	})
	if err != nil {
		return fmt.Errorf("encoding file header: %w", err)
	}

	// Dump each table
	for _, spec := range backupTables {
		err = dumpTable(ctx, tx, spec, enc)
		if err != nil {
			return fmt.Errorf("dumping table %q: %w", spec.name, err)
		}
	}

	// Write the checksum as trailer
	_, err = w.Write(h.Sum(nil))
	if err != nil {
		return fmt.Errorf("writing backup checksum: %w", err)
	}

	return nil
}

// dumpTable writes a single table block (header + rows + end-of-table sentinel) to enc
func dumpTable(ctx context.Context, tx adapter.Querier, spec tableSpec, enc *cbor.Encoder) error {
	colNames := spec.columnNames()

	err := enc.Encode(tableHeader{
		Name:    spec.name,
		Columns: colNames,
	})
	if err != nil {
		return fmt.Errorf("encoding table header: %w", err)
	}

	query := "SELECT " + strings.Join(colNames, ", ") + " FROM " + spec.name
	rows, err := tx.Query(ctx, query)
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
