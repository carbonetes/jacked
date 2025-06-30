package base

import (
	"context"
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/scan/matcher/version"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
	"github.com/carbonetes/jacked/pkg/model"
)

// Matcher provides common functionality for all vulnerability matchers
type Matcher struct {
	matcherType matchertypes.MatcherType
	store       db.Store
	config      Config
}

// Config holds configuration for base matcher
type Config struct {
	UseCPEs                     bool
	MaxConcurrency              int
	EnableCaching               bool
	SearchMavenUpstream         bool
	SearchMavenBySHA            bool
	AlwaysUseCPEForStdlib       bool
	AllowMainModulePseudoVersion bool
}

// NewMatcher creates a new base matcher
func NewMatcher(matcherType matchertypes.MatcherType, store db.Store, config Config) *Matcher {
	return &Matcher{
		matcherType: matcherType,
		store:       store,
		config:      config,
	}
}

// Type returns the matcher type
func (m *Matcher) Type() matchertypes.MatcherType {
	return m.matcherType
}

// FindMatches is the main entry point for finding vulnerability matches
func (m *Matcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	var allMatches []matchertypes.Match
	
	for _, pkg := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		
		matches, err := m.matchPackage(ctx, pkg, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to match package %s: %w", pkg.Name, err)
		}
		
		allMatches = append(allMatches, matches...)
	}
	
	return &matchertypes.MatchResults{
		Matches: allMatches,
		Summary: matchertypes.MatchSummary{
			TotalMatches: len(allMatches),
		},
	}, nil
}

// matchPackage finds matches for a single package
func (m *Matcher) matchPackage(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	var allMatches []matchertypes.Match
	
	// Try exact ecosystem match first
	ecosystemMatches, err := m.findEcosystemMatches(ctx, pkg, opts)
	if err != nil {
		return nil, err
	}
	allMatches = append(allMatches, ecosystemMatches...)
	
	// Try CPE match if enabled
	if m.config.UseCPEs && opts.CPEMatching {
		cpeMatches, err := m.findCPEMatches(ctx, pkg, opts)
		if err != nil {
			return nil, err
		}
		allMatches = append(allMatches, cpeMatches...)
	}
	
	return allMatches, nil
}

// findEcosystemMatches finds vulnerabilities by ecosystem/language matching
func (m *Matcher) findEcosystemMatches(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	var matches []matchertypes.Match
	
	// Query vulnerabilities using the appropriate store method based on ecosystem
	var vulnerabilities *[]model.Vulnerability
	
	switch pkg.Ecosystem {
	case "npm":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "maven", "java":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "pypi", "python":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "rubygems", "gem":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "go":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "dart", "pub":
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	case "apk":
		vulnerabilities = m.store.ApkSecDBMatch(pkg.Name)
	case "deb", "dpkg":
		vulnerabilities = m.store.DebSecTrackerMatch(pkg.Name)
	default:
		vulnerabilities = m.store.NVDMatchWithKeywords([]string{pkg.Name})
	}
	
	if vulnerabilities == nil {
		return matches, nil
	}
	
	for _, vuln := range *vulnerabilities {
		if m.isVersionMatch(pkg.Version, vuln.Constraints) {
			match := matchertypes.Match{
				Vulnerability: m.convertToMatcherVuln(vuln, pkg.Ecosystem),
				Package:       pkg,
				Details: []matchertypes.MatchDetail{
					{
						Type:       matchertypes.ExactDirectMatch,
						Confidence: 1.0,
						SearchedBy: map[string]interface{}{
							"ecosystem": pkg.Ecosystem,
							"package":   pkg.Name,
							"version":   pkg.Version,
						},
						Found: map[string]interface{}{
							"vulnerability_id":   vuln.CVE,
							"version_constraint": vuln.Constraints,
						},
						Matcher: string(m.matcherType),
					},
				},
			}
			matches = append(matches, match)
		}
	}
	
	return matches, nil
}

// findCPEMatches finds vulnerabilities by CPE matching
func (m *Matcher) findCPEMatches(ctx context.Context, pkg matchertypes.Package, opts matchertypes.MatchOptions) ([]matchertypes.Match, error) {
	if len(pkg.CPEs) == 0 {
		return nil, nil
	}
	
	var allMatches []matchertypes.Match
	
	for _, cpe := range pkg.CPEs {
		// Use NVD matching with CPE keywords
		vulnerabilities := m.store.NVDMatchWithKeywords([]string{cpe})
		if vulnerabilities == nil {
			continue
		}
		
		for _, vuln := range *vulnerabilities {
			if m.isVersionMatch(pkg.Version, vuln.Constraints) {
				match := matchertypes.Match{
					Vulnerability: m.convertToMatcherVuln(vuln, pkg.Ecosystem),
					Package:       pkg,
					Details: []matchertypes.MatchDetail{
						{
							Type:       matchertypes.CPEMatch,
							Confidence: 0.9,
							SearchedBy: map[string]interface{}{
								"cpe":     cpe,
								"package": pkg.Name,
								"version": pkg.Version,
							},
							Found: map[string]interface{}{
								"vulnerability_id":   vuln.CVE,
								"version_constraint": vuln.Constraints,
								"cpe":                cpe,
							},
							Matcher: string(m.matcherType),
						},
					},
				}
				allMatches = append(allMatches, match)
			}
		}
	}
	
	return allMatches, nil
}

// isVersionMatch checks if a package version matches the vulnerability constraint
func (m *Matcher) isVersionMatch(packageVersion, constraintStr string) bool {
	if constraintStr == "" {
		return false
	}
	
	constraints, err := version.Parse(constraintStr)
	if err != nil {
		return len(strings.TrimSpace(constraintStr)) > 0
	}
	
	return version.Check(packageVersion, constraints)
}

// convertToMatcherVuln converts a database vulnerability to a matcher vulnerability
func (m *Matcher) convertToMatcherVuln(dbVuln model.Vulnerability, ecosystem string) matchertypes.Vulnerability {
	var relatedVulns []matchertypes.VulnerabilityRef
	for _, advisory := range dbVuln.Advisories {
		relatedVulns = append(relatedVulns, matchertypes.VulnerabilityRef{
			ID:        advisory,
			Namespace: m.determineNamespace(ecosystem, dbVuln.Distro),
		})
	}
	
	return matchertypes.Vulnerability{
		ID:                fmt.Sprintf("%d", dbVuln.ID),
		Namespace:         m.determineNamespace(ecosystem, dbVuln.Distro),
		PackageName:       dbVuln.Package,
		VersionConstraint: dbVuln.Constraints,
		CPEs:              dbVuln.CPE,
		RelatedVulnerabilities: relatedVulns,
		Fix: matchertypes.Fix{
			State:   m.determineFixState(dbVuln),
			Version: m.getFixedVersion(dbVuln),
		},
		Advisories: []matchertypes.Advisory{},
		Metadata: map[string]interface{}{
			"severity":    dbVuln.Severity,
			"cvss_score":  m.getCVSSScore(dbVuln),
			"description": dbVuln.Description,
			"source":      dbVuln.Source,
		},
	}
}

// determineNamespace determines the appropriate namespace for a vulnerability
func (m *Matcher) determineNamespace(ecosystem, distro string) string {
	if distro != "" {
		return fmt.Sprintf("%s:distro:%s", ecosystem, distro)
	}
	
	switch ecosystem {
	case "npm":
		return "npm"
	case "maven", "java":
		return "maven"
	case "pypi", "python":
		return "pypi"
	case "rubygems", "gem":
		return "rubygems"
	case "go":
		return "go"
	case "dart", "pub":
		return "pub"
	case "apk":
		return "alpine:distro:alpine"
	case "deb", "dpkg":
		return "debian:distro:debian"
	case "rpm":
		return "rhel:distro:rhel"
	default:
		return "unknown"
	}
}

// determineFixState determines the fix state based on available fixes
func (m *Matcher) determineFixState(vuln model.Vulnerability) matchertypes.FixState {
	if len(vuln.Fixes) > 0 {
		return matchertypes.FixStateFixed
	}
	return matchertypes.FixStateNotFixed
}

// getFixedVersion gets the fixed version from vulnerability data
func (m *Matcher) getFixedVersion(vuln model.Vulnerability) string {
	if len(vuln.Fixes) > 0 {
		return vuln.Fixes[0]
	}
	return ""
}

// getCVSSScore extracts the CVSS score from vulnerability data
func (m *Matcher) getCVSSScore(vuln model.Vulnerability) float64 {
	if len(vuln.CVSS) > 0 {
		return vuln.CVSS[0].Score
	}
	return 0.0
}
