package db

import (
	"database/sql"
	"os"
	"path"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
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
	dbFilepath   = os.Getenv("JACKED_DB")
)

func init() {
	if dbFilepath == "" {
		dbFilepath = path.Join(dbDirectory, dbFile)
		os.Setenv("JACKED_DB", dbFilepath)
	}

}

func Load() {
	sqldb, err := sql.Open(sqliteshim.ShimName, dbFilepath)
	if err != nil {
		log.Fatalf("error establishing database connection: %v", err)
	}

	db = bun.NewDB(sqldb, sqlitedialect.New())

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("error pinging database: %v", err)
	}
}
