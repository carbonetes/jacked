package db

import (
	"context"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/uptrace/bun"
)

func (s *Store) ApkSecDBMatch(name string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package = ? AND source = 'alpine'", name).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) ApkSecDBMatchByKeywords(keywords []string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'alpine'", bun.In(keywords)).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}

func (s *Store) ApkSecDBMatchWithKeywordsAndDistroVersion(keywords []string, version string) *[]model.Vulnerability {
	vulnerabilities := new([]model.Vulnerability)
	if err := db.NewSelect().Model(vulnerabilities).Where("package IN (?) AND source = 'alpine' AND distro_version = ?", bun.In(keywords), version).Scan(context.Background()); err != nil {
		log.Fatal(err)
	}

	return vulnerabilities
}
