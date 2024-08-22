package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/uptrace/bun"
)

func (s *Store) NVDMatchWithKeywords(keywords []string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'nvd'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) NVDMatchCVEsWithKeywords(keywords []string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("cve IN (?) AND source = 'nvd'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
