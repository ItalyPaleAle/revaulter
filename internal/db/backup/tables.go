package backup

import (
	"github.com/italypaleale/revaulter/internal/db"
)

// columnKind describes the semantic type of a column for cross-database portability
type columnKind uint8

const (
	colKindText columnKind = iota // TEXT / string (default)
	colKindBool                   // BOOLEAN (SQLite stores as INTEGER 0/1)
	colKindUUID                   // UUID (Postgres uses native uuid type)
	colKindJSON                   // JSON/JSONB (Postgres uses jsonb type)
)

type columnSpec struct {
	name string
	kind columnKind
}

type tableSpec struct {
	name    string
	columns []columnSpec
}

// rowFilter narrows which rows of a table are included in a backup
type rowFilter struct {
	where string
	args  []any
}

// rowFilters lists the tables that are backed up in part rather than in full, keyed by table name
var rowFilters = map[string]rowFilter{
	// Ignore the audit log cursor from the KV table
	"v2_kv": {
		where: "key <> $1",
		args:  []any{db.AuditStreamCursorKey},
	},
}

// columnNames returns just the name slice for a table spec
func (t tableSpec) columnNames() []string {
	names := make([]string, len(t.columns))
	for i, c := range t.columns {
		names[i] = c.name
	}
	return names
}
