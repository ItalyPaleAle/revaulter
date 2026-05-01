// gen introspects a freshly-migrated SQLite and Postgres database to generate tables_gen.go in the parent backup package
// Run via: TEST_DATABASE_DSN=<dsn> go generate ./pkg/db/backup/
package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"go/format"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/italypaleale/go-sql-utils/adapter"
	postgresadapter "github.com/italypaleale/go-sql-utils/adapter/postgres"
	sqladapter "github.com/italypaleale/go-sql-utils/adapter/sql"
	"github.com/jackc/pgx/v5/pgxpool"

	// Blank import for the SQLite driver
	_ "modernc.org/sqlite"
)

// skipTables lists tables intentionally excluded from backups because they hold ephemeral data (short-lived auth challenges) that has no value after expiry
var skipTables = map[string]bool{
	"v2_auth_challenges":         true,
	"v2_auth_challenge_payloads": true,
}

// postgresUDTToKind maps Postgres udt_name values (from information_schema) to the columnKind constant used by the backup library
var postgresUDTToKind = map[string]string{
	"bool":    "colKindBool",
	"boolean": "colKindBool",
	"uuid":    "colKindUUID",
	"jsonb":   "colKindJSON",
}

type column struct {
	name string
	kind string // Go constant, e.g. "colKindText"
}

type table struct {
	name    string
	columns []column
	// fkTargets is the set of table names this table has FK references to
	fkTargets map[string]bool
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The generator is invoked by go:generate from the backup package directory
	sqliteMigrationsDir := filepath.Join("..", "migrations", "sqlite")
	postgresMigrationsDir := filepath.Join("..", "migrations", "postgres")

	// --- SQLite phase: column order + FK graph ---
	sqliteTables, err := introspectSQLite(ctx, sqliteMigrationsDir)
	if err != nil {
		log.Fatalf("SQLite introspection failed: %v", err)
	}

	// --- Postgres phase: precise column types ---
	pgDSN := os.Getenv("TEST_DATABASE_DSN")
	if pgDSN == "" {
		log.Fatalf("TEST_DATABASE_DSN is required; set it to a Postgres DSN for accurate type generation")
	}

	pgTypes, err := introspectPostgres(ctx, pgDSN, postgresMigrationsDir)
	if err != nil {
		log.Fatalf("Postgres introspection failed: %v", err)
	}

	// Merge Postgres type info into the SQLite column list
	mergePostgresTypes(sqliteTables, pgTypes)

	// --- Topological sort for FK-safe restore order ---
	ordered, err := topoSort(sqliteTables)
	if err != nil {
		log.Fatalf("topological sort failed: %v", err)
	}

	err = writeGenFile("tables_gen.go", ordered)
	if err != nil {
		log.Fatalf("writing tables_gen.go: %v", err)
	}

	log.Printf("generated tables_gen.go with %d tables", len(ordered))
}

// introspectSQLite creates an in-memory SQLite database, applies all migrations, and returns the table/column structure
func introspectSQLite(ctx context.Context, migrationsDir string) (map[string]*table, error) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()

	err = runMigrations(ctx, sqladapter.AdaptDatabaseSQLConn(db), migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("run sqlite migrations: %w", err)
	}

	// List all application tables (excluding SQLite internals and skip list)
	tableNames, err := sqliteTableNames(ctx, db)
	if err != nil {
		return nil, err
	}

	tables := make(map[string]*table, len(tableNames))
	for _, name := range tableNames {
		cols, err := sqliteColumns(ctx, db, name)
		if err != nil {
			return nil, err
		}

		fks, err := sqliteFKTargets(ctx, db, name)
		if err != nil {
			return nil, err
		}

		tables[name] = &table{
			name:      name,
			columns:   cols,
			fkTargets: fks,
		}
	}

	return tables, nil
}

func sqliteTableNames(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		err = rows.Scan(&name)
		if err != nil {
			return nil, err
		}

		// We always skip the metadata table
		if name != "metadata" && !skipTables[name] {
			names = append(names, name)
		}
	}
	return names, rows.Err()
}

func sqliteColumns(ctx context.Context, db *sql.DB, tableName string) ([]column, error) {
	// PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoteSQLiteIdent(tableName)+")")
	if err != nil {
		return nil, fmt.Errorf("table_info %s: %w", tableName, err)
	}
	defer rows.Close()

	var cols []column
	for rows.Next() {
		var (
			cid       int
			name, typ string
			notnull   int
			dflt      sql.NullString
			pk        int
		)
		err = rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk)
		if err != nil {
			return nil, err
		}

		// Map SQLite type affinity to a preliminary columnKind
		// This is overridden by the Postgres introspection when available
		kind := sqliteTypeToKind(typ)
		cols = append(cols, column{name: name, kind: kind})
	}
	return cols, rows.Err()
}

func sqliteFKTargets(ctx context.Context, db *sql.DB, tableName string) (map[string]bool, error) {
	// PRAGMA foreign_key_list returns: id, seq, table, from, to, on_update, on_delete, match
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_list("+quoteSQLiteIdent(tableName)+")")
	if err != nil {
		return nil, fmt.Errorf("foreign_key_list %s: %w", tableName, err)
	}
	defer rows.Close()

	targets := make(map[string]bool)
	for rows.Next() {
		var (
			id, seq                     int
			targetTable, fromCol, toCol string
			onUpdate, onDelete, match   string
		)
		err = rows.Scan(&id, &seq, &targetTable, &fromCol, &toCol, &onUpdate, &onDelete, &match)
		if err != nil {
			return nil, err
		}

		targets[targetTable] = true
	}
	return targets, rows.Err()
}

// pgColumnTypes maps tableName → columnName → Postgres udt_name
type pgColumnTypes map[string]map[string]string

// introspectPostgres creates a temporary schema in the target Postgres instance, applies all migrations, and returns a map of column type names
func introspectPostgres(ctx context.Context, dsn string, migrationsDir string) (pgColumnTypes, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}

	schemaName := fmt.Sprintf("gen_backup_%d", time.Now().UnixNano())

	// Create the schema using the base connection (no search_path override yet)
	basePool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	_, err = basePool.Exec(ctx, "CREATE SCHEMA "+schemaName)
	basePool.Close()
	if err != nil {
		return nil, fmt.Errorf("create schema %s: %w", schemaName, err)
	}

	// Always clean up the schema when done
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cleanCfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			return
		}

		pool, err := pgxpool.NewWithConfig(cleanCtx, cleanCfg)
		if err != nil {
			return
		}
		defer pool.Close()

		_, _ = pool.Exec(cleanCtx, "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE")
	}()

	// Reconnect with search_path pointing to the fresh schema
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to schema %s: %w", schemaName, err)
	}
	defer pool.Close()

	// Run Postgres migrations
	err = runMigrations(ctx, postgresadapter.AdaptPgxConn(pool), migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("run postgres migrations: %w", err)
	}

	// Query column types
	rows, err := pool.Query(ctx, `
		SELECT table_name, column_name, udt_name
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		return nil, fmt.Errorf("query information_schema: %w", err)
	}
	defer rows.Close()

	result := make(pgColumnTypes)
	for rows.Next() {
		var tableName, colName, udtName string
		err = rows.Scan(&tableName, &colName, &udtName)
		if err != nil {
			return nil, err
		}
		if result[tableName] == nil {
			result[tableName] = make(map[string]string)
		}
		result[tableName][colName] = udtName
	}
	return result, rows.Err()
}

// mergePostgresTypes replaces the preliminary column kinds with accurate ones derived from the Postgres information_schema
func mergePostgresTypes(tables map[string]*table, pgTypes pgColumnTypes) {
	for tableName, t := range tables {
		pgCols, ok := pgTypes[tableName]
		if !ok {
			continue
		}
		for i, col := range t.columns {
			udtName, ok := pgCols[col.name]
			if !ok {
				continue
			}
			kind, ok := postgresUDTToKind[udtName]
			if ok {
				t.columns[i].kind = kind
			}
		}
	}
}

// topoSort returns the tables in an order where every table's FK dependencies appear before it
// Tables with no dependencies come first
func topoSort(tables map[string]*table) ([]*table, error) {
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int, len(tables))
	result := make([]*table, 0, len(tables))

	// Collect names and sort for deterministic output
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)

	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case visited:
			return nil
		case visiting:
			return fmt.Errorf("cyclic FK dependency involving table %q", name)
		}
		state[name] = visiting

		t, ok := tables[name]
		if !ok {
			// FK target is a skipped table (e.g. v2_auth_challenges) — skip
			state[name] = visited
			return nil
		}

		// Visit FK dependencies first
		depNames := make([]string, 0, len(t.fkTargets))
		for dep := range t.fkTargets {
			depNames = append(depNames, dep)
		}

		sort.Strings(depNames)

		for _, dep := range depNames {
			err := visit(dep)
			if err != nil {
				return err
			}
		}

		state[name] = visited
		result = append(result, t)

		return nil
	}

	for _, name := range names {
		err := visit(name)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// runMigrations does the same as runMigrationsSQL but via pgxpool
func runMigrations(ctx context.Context, db adapter.Querier, dir string) error {
	scripts, err := loadSQLScripts(dir)
	if err != nil {
		return err
	}

	for _, script := range scripts {
		_, err = db.Exec(ctx, script)
		if err != nil {
			return fmt.Errorf("exec migration: %w", err)
		}
	}
	return nil
}

// loadSQLScripts reads all *.sql files from dir in sorted order
func loadSQLScripts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var scripts []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}

		data, err := fs.ReadFile(os.DirFS(dir), e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}

		s := strings.TrimSpace(string(data))
		if s != "" {
			scripts = append(scripts, s)
		}
	}
	return scripts, nil
}

// sqliteTypeToKind maps a SQLite column type affinity to a preliminary columnKind
// This is only used when Postgres introspection is unavailable
func sqliteTypeToKind(typ string) string {
	switch strings.ToUpper(typ) {
	case "BOOLEAN":
		return "colKindBool"
	default:
		return "colKindText"
	}
}

// quoteSQLiteIdent wraps an identifier in double-quotes for use in PRAGMA statements
func quoteSQLiteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// writeGenFile writes the generated Go source to path
func writeGenFile(path string, tables []*table) error {
	var buf bytes.Buffer

	fmt.Fprintln(&buf, "// Code generated by go generate; DO NOT EDIT.")
	fmt.Fprintln(&buf, "// Regenerate with: go generate ./pkg/db/backup/")
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "package backup")
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "// backupTables lists the persistent tables included in a backup, in FK-safe order (parents before children so that FK constraints are satisfied on restore)")
	fmt.Fprintln(&buf, "//")
	fmt.Fprintln(&buf, "// Ephemeral tables (v2_auth_challenges, v2_auth_challenge_payloads) and the metadata table are excluded from backups")
	fmt.Fprintln(&buf, "var backupTables = []tableSpec{")

	for _, t := range tables {
		fmt.Fprintf(&buf, "\t{\n")
		fmt.Fprintf(&buf, "\t\tname: %q,\n", t.name)
		fmt.Fprintf(&buf, "\t\tcolumns: []columnSpec{\n")
		for _, c := range t.columns {
			fmt.Fprintf(&buf, "\t\t\t{name: %q, kind: %s},\n", c.name, c.kind)
		}
		fmt.Fprintf(&buf, "\t\t},\n")
		fmt.Fprintf(&buf, "\t},\n")
	}

	fmt.Fprintln(&buf, "}")

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		_ = os.WriteFile(path, buf.Bytes(), 0o644)
		return fmt.Errorf("formatting generated source: %w\nraw output written for debugging", err)
	}

	err = os.WriteFile(path, formatted, 0o644)
	if err != nil {
		return err
	}

	return nil
}
