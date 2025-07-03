package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/uptrace/bun"
)

func (s *Store) GhsaDBMatchByKeywords(keywords []string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'ghsa'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
