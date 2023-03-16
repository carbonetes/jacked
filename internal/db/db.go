package db

import (
	"context"
	"database/sql"
	"os"
	"path"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/extra/bundebug"
	_ "modernc.org/sqlite"
)

const (
	driver        = "sqlite"
	defaultSchema = "v1"
	filename      = "jacked"
	filetype      = "db"
)

var (
	userCache, _ = os.UserCacheDir()
	log          = logger.GetLogger()
	schema       = defaultSchema
	db           *bun.DB
	dbDirectory  = path.Join(userCache, "jacked", schema)
	dbFile       = filename + "." + filetype
	dbFilepath   = path.Join(dbDirectory, dbFile)
)

func init() {
	sqldb, err := sql.Open(driver, dbFilepath)
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
	db = bun.NewDB(sqldb, sqlitedialect.New())
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
}

// Fetch all vulnerabilities in database based on the list of keywords from packages
func Fetch(keyword string, vulnerabilities *[]model.Vulnerability) error {
	ctx := context.Background()
	if err := db.NewSelect().Model(vulnerabilities).Where("packages LIKE ?", "%/"+keyword+"%").Scan(ctx); err != nil {
		return err
	}
	return nil
}
