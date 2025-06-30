package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/uptrace/bun"
)

func (s *Store) DebSecTrackerMatch(name string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package = ? AND source = 'debian'", name).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) DebSecTrackerMatchWithKeywords(keywords []string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'debian'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) DebSecTrackerMatchWithKeywordsAndDistroVersion(keywords []string, version string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'debian' AND distro_version = ?", bun.In(keywords), version).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
