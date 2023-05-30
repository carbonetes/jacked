package db

import (
	"context"
	"database/sql"
	"os"
	"path"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/pkg/core/model"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

const (
	driver        = "sqlite"
	filename      = "jacked"
	filetype      = "db"
)

var (
	userCache, _ = os.UserCacheDir()
	log          = logger.GetLogger()
	db           *bun.DB
	dbDirectory  = path.Join(userCache, filename)
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
}

// Fetch all vulnerabilities in database based on the list of keywords from packages
func Fetch(packages *[]dm.Package, vulnerabilities *[]model.Vulnerability, signatures *map[string]model.Signature) error {
	ctx := context.Background()
	var keywords []string
	for _, p := range *packages {
		signature := (*signatures)[p.ID]
		if len(signature.Keywords) == 0 {
			keywords = append(keywords, p.Name)
			continue
		}
		keywords = append(keywords, signature.Keywords...)
	}
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?)", bun.In(keywords)).Scan(ctx); err != nil {
		return err
	}
	return nil
}
