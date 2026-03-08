package v2db

import (
	"errors"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
)

type BackendKind string

const (
	BackendSQLite   BackendKind = "sqlite"
	BackendPostgres BackendKind = "postgres"
)

type ParsedDSN struct {
	Original string
	Backend  BackendKind

	// SQLite only
	SQLitePath string
	// Postgres only (passed through to pgx)
	PostgresDSN string
}

func InferDSN(raw string) (ParsedDSN, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ParsedDSN{}, errors.New("database DSN is empty")
	}

	// No scheme => local SQLite file path.
	if !strings.Contains(raw, "://") {
		return ParsedDSN{
			Original:   raw,
			Backend:    BackendSQLite,
			SQLitePath: filepath.Clean(raw),
		}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ParsedDSN{}, err
	}

	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
		return ParsedDSN{
			Original:    raw,
			Backend:     BackendPostgres,
			PostgresDSN: raw,
		}, nil
	case "sqlite":
		p, err := sqlitePathFromURL(u)
		if err != nil {
			return ParsedDSN{}, err
		}
		return ParsedDSN{
			Original:   raw,
			Backend:    BackendSQLite,
			SQLitePath: p,
		}, nil
	default:
		return ParsedDSN{}, errors.New("unsupported database DSN scheme: " + u.Scheme)
	}
}

func sqlitePathFromURL(u *url.URL) (string, error) {
	if u == nil {
		return "", errors.New("nil URL")
	}

	// Accept:
	// sqlite:///abs/path.db
	// sqlite://relative/path.db
	// sqlite://./relative.db
	// sqlite://C:/path/db.sqlite (Windows)
	var p string
	switch {
	case u.Opaque != "":
		p = u.Opaque
	case u.Host != "" && u.Path != "":
		p = u.Host + u.Path
	case u.Host != "":
		p = u.Host
	default:
		p = u.Path
	}
	if p == "" {
		return "", errors.New("sqlite DSN does not contain a path")
	}

	// url.Parse preserves a leading slash for unix absolute paths; keep it.
	// For Windows "C:/..." paths, url parsing may yield "/C:/..."; normalize.
	if runtime.GOOS == "windows" && strings.HasPrefix(p, "/") && len(p) > 3 && p[2] == ':' {
		p = p[1:]
	}

	return filepath.Clean(p), nil
}
