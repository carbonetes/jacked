package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/uptrace/bun"
)

// FindPackage is a function that accepts a list of keywords and a list of Vulnerability structs.
// It uses the bun package to query the database for vulnerabilities that match any of the keywords.
// If there is an error while querying the database, the function logs the error as fatal.
func FindByKeywords(keywords *[]string, vulnerabilities *[]model.Vulnerability) {
	// Use db.NewSelect() to create a new select query on the vulnerabilities table.
	// Then use .Model(vulnerabilities) to specify the destination struct for the query results.
	// Use .Where("package IN (?)", bun.In(keywords)) to filter the query results by looking for vulnerabilities where the "package" field matches any of the keywords.
	// Finally, use .Scan(context.Background()) to execute the query and scan the results into the vulnerabilities struct.
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?)", bun.In(*keywords)).Scan(context.Background()); err != nil {
		// If there is an error while executing the query, log it as fatal.
		log.Fatal(err)
	}
}
