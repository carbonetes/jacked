package db

import (
	"database/sql"
	"os"
	"path"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

const (
	driver   = "sqlite"
	filename = "jacked"
	filetype = "db"
)

var (
	userCache, _ = os.UserCacheDir()
	db           *bun.DB
	dbDirectory  = path.Join(userCache, filename)
	dbFile       = filename + "." + filetype
	dbFilepath = os.Getenv("JACKED_DB")
)

func init() {
	if dbFilepath == "" {
		dbFilepath = path.Join(dbDirectory, dbFile)
		os.Setenv("JACKED_DB", dbFilepath)
	}

	sqldb, err := sql.Open(driver, dbFilepath)
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
	db = bun.NewDB(sqldb, sqlitedialect.New())
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
}
