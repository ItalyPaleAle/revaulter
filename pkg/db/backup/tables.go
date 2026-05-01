package backup

// columnKind describes the semantic type of a column for cross-database portability
type columnKind uint8

const (
	colKindText columnKind = iota // TEXT / string (default)
	colKindBool                   // BOOLEAN — SQLite stores as INTEGER 0/1
	colKindUUID                   // UUID — Postgres uses native uuid type
	colKindJSONB                  // JSON/JSONB — Postgres uses jsonb type
)

type columnSpec struct {
	name string
	kind columnKind
}

type tableSpec struct {
	name    string
	columns []columnSpec
}

// columnNames returns just the name slice for a table spec
func (t tableSpec) columnNames() []string {
	names := make([]string, len(t.columns))
	for i, c := range t.columns {
		names[i] = c.name
	}
	return names
}
