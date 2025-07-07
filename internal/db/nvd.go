package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/uptrace/bun"
)

// NVDMatchWithKeywords performs optimized vulnerability lookup with caching
func (s *Store) NVDMatchWithKeywords(keywords []string) *[]model.Vulnerability {
	if len(keywords) == 0 {
		return &[]model.Vulnerability{}
	}

	// Use batch lookup for better performance
	results := s.BatchVulnerabilityLookup(keywords, "nvd")

	// Merge all results
	var allVulns []model.Vulnerability
	for _, vulns := range results {
		if vulns != nil {
			allVulns = append(allVulns, *vulns...)
		}
	}

	return &allVulns
}

// NVDMatchCVEsWithKeywords looks up vulnerabilities by CVE IDs
func (s *Store) NVDMatchCVEsWithKeywords(keywords []string) *[]model.Vulnerability {
	if len(keywords) == 0 {
		return &[]model.Vulnerability{}
	}

	// Check cache first
	cacheKey := fmt.Sprintf("nvd:cves:%s", strings.Join(keywords, "|"))
	if cached, found := getCachedVulnerabilities(cacheKey); found {
		return cached
	}

	vulnerabilities := new([]model.Vulnerability)

	// Use batched query for better performance
	const batchSize = 100
	for i := 0; i < len(keywords); i += batchSize {
		end := i + batchSize
		if end > len(keywords) {
			end = len(keywords)
		}

		batch := keywords[i:end]
		var batchVulns []model.Vulnerability

		if err := db.NewSelect().
			Model(&batchVulns).
			Where("cve IN (?) AND source = 'nvd'", bun.In(batch)).
			Scan(context.Background()); err != nil {
			log.Debugf("Error in NVD CVE lookup batch: %v", err)
			continue
		}

		*vulnerabilities = append(*vulnerabilities, batchVulns...)
	}

	// Cache the results
	setCachedVulnerabilities(cacheKey, vulnerabilities)

	return vulnerabilities
}

// NVDMatchWithPackageNames performs optimized package name lookup
func (s *Store) NVDMatchWithPackageNames(names []string) *[]model.Vulnerability {
	if len(names) == 0 {
		return &[]model.Vulnerability{}
	}

	// Use batch lookup for better performance
	results := s.BatchVulnerabilityLookup(names, "nvd")

	// Merge all results
	var allVulns []model.Vulnerability
	for _, vulns := range results {
		if vulns != nil {
			allVulns = append(allVulns, *vulns...)
		}
	}

	return &allVulns
}

// NVDBatchLookup performs highly optimized batch vulnerability lookup
func (s *Store) NVDBatchLookup(packages []string, useCaching bool) map[string]*[]model.Vulnerability {
	if len(packages) == 0 {
		return make(map[string]*[]model.Vulnerability)
	}

	if useCaching {
		return s.BatchVulnerabilityLookup(packages, "nvd")
	}

	// Direct database lookup without caching
	results := make(map[string]*[]model.Vulnerability)

	// Initialize results map
	for _, pkg := range packages {
		results[pkg] = &[]model.Vulnerability{}
	}

	// Query in batches for memory efficiency
	const batchSize = 200
	for i := 0; i < len(packages); i += batchSize {
		end := i + batchSize
		if end > len(packages) {
			end = len(packages)
		}

		batch := packages[i:end]
		vulnerabilities := make([]model.Vulnerability, 0)

		query := db.NewSelect().
			Model(&vulnerabilities).
			Where("package IN (?) AND source = 'nvd'", bun.In(batch))

		if err := query.Scan(context.Background()); err != nil {
			log.Debugf("Error in NVD batch lookup: %v", err)
			continue
		}

		// Group results by package
		for _, vuln := range vulnerabilities {
			if packageVulns, exists := results[vuln.Package]; exists {
				*packageVulns = append(*packageVulns, vuln)
			}
		}
	}

	return results
}

// NVDMatchWithConstraints performs filtered vulnerability lookup with constraint matching
func (s *Store) NVDMatchWithConstraints(packages []string, constraints map[string]string) *[]model.Vulnerability {
	if len(packages) == 0 {
		return &[]model.Vulnerability{}
	}

	// Create cache key including constraints
	cacheKey := fmt.Sprintf("nvd:constrained:%s", strings.Join(packages, "|"))
	if cached, found := getCachedVulnerabilities(cacheKey); found {
		return cached
	}

	vulnerabilities := new([]model.Vulnerability)

	// Build query with constraint filtering
	query := db.NewSelect().
		Model(vulnerabilities).
		Where("package IN (?) AND source = 'nvd'", bun.In(packages))

	// Add constraint filtering if provided
	if len(constraints) > 0 {
		var constraintConditions []string
		var constraintValues []interface{}

		for pkg, constraint := range constraints {
			if constraint != "" {
				constraintConditions = append(constraintConditions, "(package = ? AND constraints LIKE ?)")
				constraintValues = append(constraintValues, pkg, "%"+constraint+"%")
			}
		}

		if len(constraintConditions) > 0 {
			query = query.Where("("+strings.Join(constraintConditions, " OR ")+")", constraintValues...)
		}
	}

	if err := query.Scan(context.Background()); err != nil {
		log.Debugf("Error in NVD constrained lookup: %v", err)
		return &[]model.Vulnerability{}
	}

	// Cache the results
	setCachedVulnerabilities(cacheKey, vulnerabilities)

	return vulnerabilities
}
