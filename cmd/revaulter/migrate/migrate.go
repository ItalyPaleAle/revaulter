package migrate

import (
	"context"
	"errors"
	"log/slog"
	"time"

	slogkit "github.com/italypaleale/go-kit/slog"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
)

// Run opens the database and runs migrations
func Run(log *slog.Logger) {
	// Ensure the database is configured
	conf := config.Get()
	if conf.DatabaseDSN == "" {
		slogkit.FatalError(log, "Invalid configuraiton", errors.New("databaseDSN is required"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Connect to the database
	dbConn, err := db.Open(ctx, conf.DatabaseDSN)
	if err != nil {
		slogkit.FatalError(log, "Failed to open database", err)
		return
	}
	defer dbConn.Close(ctx)

	// Run migrations
	err = db.RunMigrations(ctx, dbConn, log)
	if err != nil {
		slogkit.FatalError(log, "Failed to run database migrations", err)
		return
	}

	log.Info("Database migrations completed successfully")
}
