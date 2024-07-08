package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/uptrace/bun"
)

func (s *Store) GhsaDBMatchByKeywords(keywords []string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'ghsa'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
