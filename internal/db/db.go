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
func Fetch(packages *[]model.Package, vulnerabilities *[]model.Vulnerability) error {
	ctx := context.Background()
	var keywords []string
	for _, p := range *packages {
		keywords = append(keywords, p.Keywords...)
	}
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?)", bun.In(keywords)).Scan(ctx); err != nil {
		return err
	}
	return nil
}

// FindPackage is a function that takes in a package name and a pointer to a slice of Vulnerability objects, and queries the database for vulnerabilities associated with that package.
// Input: a string representing the package name, and a pointer to a slice of `model.Vulnerability` objects.
// Output: None (the results are stored in the `vulnerabilities` slice).
func FindPackage(pkgName string, vulnerabilities *[]model.Vulnerability) {
    // Query the database using the `NewSelect()` method from the `db` package's API, passing in the `vulnerabilities` slice as the destination for the query results. Limit the results to those where the package name matches `pkgName`.
    // If an error occurs during querying, log the error and exit the program with an error status code.
    if err := db.NewSelect().Model(vulnerabilities).Where("package = ?", pkgName).Scan(context.Background()); err != nil {
        log.Fatal(err)
    }
}