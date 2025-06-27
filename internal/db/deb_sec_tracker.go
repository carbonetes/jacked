package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/uptrace/bun"
)

func (s *Store) DebSecTrackerMatch(name string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package = ? AND source = 'debian'", name).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) DebSecTrackerMatchWithKeywords(keywords []string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'debian'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) DebSecTrackerMatchWithKeywordsAndDistroVersion(keywords []string, version string) *[]types.Vulnerability {
	vulnerabilities := new([]types.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'debian' AND distro_version = ?", bun.In(keywords), version).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
