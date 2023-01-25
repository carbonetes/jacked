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
	conn, err := sql.Open(driver, dbFilepath)
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
	db = bun.NewDB(conn, sqlitedialect.New())
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}
}

// Fetch all vulnerabilities in database based on the list of keywords from packages
func Fetch(packages *[]model.Package, vulnerabilities *[]model.Vulnerability) {
	ctx := context.Background()
	var keywords []string
	for _, p := range *packages {
		keywords = append(keywords, p.Keywords...)
	}
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?)", bun.In(keywords)).Scan(ctx); err != nil {
		log.Fatalf("Error getting vulnerabilities: %v", err)
	}
}
