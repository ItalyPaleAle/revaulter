package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/spf13/pflag"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	dbbackup "github.com/italypaleale/revaulter/pkg/db/backup"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
)

// dbOpenTimeout caps how long we wait for the initial database connection
const dbOpenTimeout = 20 * time.Second

// RunBackup opens the database and writes a backup to stdout or to the path given via --out
func RunBackup(log *slog.Logger, args []string) {
	flags := pflag.NewFlagSet("backup", pflag.ExitOnError)

	var out string
	flags.StringVarP(&out, "out", "o", "", "path to write the backup to (defaults to stdout)")

	// Parse flags
	err := flags.Parse(args)
	if err != nil {
		slogkit.FatalError(log, "Failed to parse arguments", err)
		return
	}

	// Ensure the database is configured
	conf := config.Get()
	if conf.DatabaseDSN == "" {
		slogkit.FatalError(log, "Invalid configuration", errors.New("databaseDSN is required"))
		return
	}

	// Get the stream to the writer
	w, closeFn, err := openWriter(out)
	if err != nil {
		slogkit.FatalError(log, "Failed to open output", err)
		return
	}
	defer closeFn()

	ctx := logging.LogToContext(context.Background(), log)

	// Connect to the database
	connCtx, connCancel := context.WithTimeout(ctx, dbOpenTimeout)
	dbConn, err := db.Open(connCtx, conf.DatabaseDSN)
	connCancel()
	if err != nil {
		slogkit.FatalError(log, "Failed to open database", err)
		return
	}
	defer dbConn.Close(ctx)

	// Perform the backup
	err = dbbackup.Backup(ctx, dbConn.DatabaseConn, w)
	if err != nil {
		slogkit.FatalError(log, "Failed to perform backup", err)
		return
	}

	log.Info("Backup completed successfully")
}

// RunRestore opens the database and restores a backup read from stdin or from the path given via --in
func RunRestore(log *slog.Logger, args []string) {
	flags := pflag.NewFlagSet("restore", pflag.ExitOnError)

	var in string
	flags.StringVarP(&in, "in", "i", "", "path to read the backup from (defaults to stdin)")

	// Parse flags
	err := flags.Parse(args)
	if err != nil {
		slogkit.FatalError(log, "Failed to parse arguments", err)
		return
	}

	// Ensure the database is configured
	conf := config.Get()
	if conf.DatabaseDSN == "" {
		slogkit.FatalError(log, "Invalid configuration", errors.New("databaseDSN is required"))
		return
	}

	// Get the stream to the reader
	r, closeFn, err := openReader(in)
	if err != nil {
		slogkit.FatalError(log, "Failed to open input", err)
		return
	}
	defer closeFn()

	ctx := logging.LogToContext(context.Background(), log)

	// Connect to the database
	connCtx, connCancel := context.WithTimeout(ctx, dbOpenTimeout)
	dbConn, err := db.Open(connCtx, conf.DatabaseDSN)
	connCancel()
	if err != nil {
		slogkit.FatalError(log, "Failed to open database", err)
		return
	}
	defer dbConn.Close(ctx)

	// Restore from backup
	err = dbbackup.Restore(ctx, dbConn, r)
	if err != nil {
		slogkit.FatalError(log, "Failed to restore backup", err)
		return
	}

	log.Info("Restore completed successfully")
}

func openWriter(path string) (w io.Writer, closeFn func(), err error) {
	if path == "" {
		// If no path, use stdout
		return os.Stdout, func() {}, nil
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %q: %w", path, err)
	}

	closeFn = func() {
		_ = f.Close()
	}
	return f, closeFn, nil
}

func openReader(path string) (r io.Reader, closeFn func(), err error) {
	if path == "" {
		// If no path, use stdin
		return os.Stdin, func() {}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %q: %w", path, err)
	}

	closeFn = func() {
		_ = f.Close()
	}
	return f, closeFn, nil
}
