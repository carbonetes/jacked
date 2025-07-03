package matcher

import (
	"context"
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/model"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// Type aliases for types not already defined in engine.go
type (
	Fix       = matchertypes.Fix
	FixState  = matchertypes.FixState
	MatchType = matchertypes.MatchType
)

// Local interfaces to avoid circular dependencies
type SearchCriteriaInterface interface {
	Apply(query *VulnerabilityQueryStruct) error
}

type VulnerabilityQueryStruct struct {
	PackageName    string                   `json:"package_name,omitempty"`
	PackageType    matchertypes.PackageType `json:"package_type,omitempty"`
	Namespace      string                   `json:"namespace,omitempty"`
	CPE            string                   `json:"cpe,omitempty"`
	DistroType     string                   `json:"distro_type,omitempty"`
	DistroVersion  string                   `json:"distro_version,omitempty"`
	OnlyFixed      bool                     `json:"only_fixed"`
	OnlyVulnerable bool                     `json:"only_vulnerable"`
	Filters        map[string]string        `json:"filters,omitempty"`
}

// BaseMatcher provides common functionality for all vulnerability matchers
type BaseMatcher struct {
	matcherType MatcherType
	store       db.Store
	config      BaseMatcherConfig
}

// BaseMatcherConfig holds configuration for base matcher
type BaseMatcherConfig struct {
	UseCPEs                      bool
	MaxConcurrency               int
	EnableCaching                bool
	SearchMavenUpstream          bool
	SearchMavenBySHA             bool
	AlwaysUseCPEForStdlib        bool
	AllowMainModulePseudoVersion bool
}

// NewBaseMatcher creates a new base matcher
func NewBaseMatcher(matcherType MatcherType, store db.Store, config BaseMatcherConfig) *BaseMatcher {
	return &BaseMatcher{
		matcherType: matcherType,
		store:       store,
		config:      config,
	}
}

// Type returns the matcher type
func (m *BaseMatcher) Type() MatcherType {
	return m.matcherType
}

// FindMatches is the main entry point for finding vulnerability matches
func (m *BaseMatcher) FindMatches(ctx context.Context, packages []Package, opts MatchOptions) (*MatchResults, error) {
	var allMatches []Match

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

	return &MatchResults{
		Matches: allMatches,
		Summary: MatchSummary{
			TotalMatches: len(allMatches),
		},
	}, nil
}

// matchPackage finds matches for a single package
func (m *BaseMatcher) matchPackage(ctx context.Context, pkg Package, opts MatchOptions) ([]Match, error) {
	var allMatches []Match

	// Try exact ecosystem match first
	ecosystemMatches, err := m.matchByEcosystem(ctx, pkg, opts)
	if err != nil {
		return nil, err
	}
	allMatches = append(allMatches, ecosystemMatches...)

	// Try CPE match if enabled
	if m.config.UseCPEs && opts.CPEMatching {
		cpeMatches, err := m.matchByCPE(ctx, pkg, opts)
		if err != nil {
			return nil, err
		}
		allMatches = append(allMatches, cpeMatches...)
	}

	return allMatches, nil
}

// matchByEcosystem matches vulnerabilities by ecosystem and package name
func (m *BaseMatcher) matchByEcosystem(ctx context.Context, pkg Package, opts MatchOptions) ([]Match, error) {
	// Create search criteria for ecosystem matching
	criteria := NewEcosystemSearchCriteria(pkg.Ecosystem, pkg.Name)

	// Add distro information if available
	if opts.DistroType != "" && opts.DistroVersion != "" {
		criteria = criteria.WithDistro(opts.DistroType, opts.DistroVersion)
	}

	// Search for vulnerabilities
	vulns, err := m.searchVulnerabilities(ctx, criteria)
	if err != nil {
		return nil, err
	}

	var matches []Match
	for _, vuln := range vulns {
		if m.isVersionVulnerable(pkg.Version, vuln.VersionConstraint) {
			match := Match{
				Vulnerability: vuln,
				Package:       pkg,
				Details: []MatchDetail{
					{
						Type:       matchertypes.ExactDirectMatch,
						Confidence: 1.0,
						SearchedBy: map[string]interface{}{
							"ecosystem": pkg.Ecosystem,
							"package":   map[string]string{"name": pkg.Name, "version": pkg.Version},
							"namespace": vuln.Namespace,
						},
						Found: map[string]interface{}{
							"vulnerabilityID":   vuln.ID,
							"versionConstraint": vuln.VersionConstraint,
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

// matchByCPE matches vulnerabilities using CPE identifiers
func (m *BaseMatcher) matchByCPE(ctx context.Context, pkg Package, opts MatchOptions) ([]Match, error) {
	if len(pkg.CPEs) == 0 {
		return nil, nil
	}

	var allMatches []Match

	for _, cpe := range pkg.CPEs {
		criteria := NewCPESearchCriteria(cpe)

		vulns, err := m.searchVulnerabilities(ctx, criteria)
		if err != nil {
			return nil, err
		}

		for _, vuln := range vulns {
			if m.isVersionVulnerable(pkg.Version, vuln.VersionConstraint) {
				match := Match{
					Vulnerability: vuln,
					Package:       pkg,
					Details: []MatchDetail{
						{
							Type:       matchertypes.CPEMatch,
							Confidence: 0.9, // CPE matches are slightly less confident
							SearchedBy: map[string]interface{}{
								"cpe":       cpe,
								"namespace": vuln.Namespace,
								"package":   map[string]string{"name": pkg.Name, "version": pkg.Version},
							},
							Found: map[string]interface{}{
								"vulnerabilityID":   vuln.ID,
								"versionConstraint": vuln.VersionConstraint,
								"cpe":               cpe,
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

// searchVulnerabilities searches for vulnerabilities using the given criteria
func (m *BaseMatcher) searchVulnerabilities(ctx context.Context, criteria SearchCriteriaInterface) ([]Vulnerability, error) {
	// Convert from internal types to search criteria
	// This is a simplified implementation - in practice, this would interface with the database

	switch c := criteria.(type) {
	case *EcosystemSearchCriteria:
		return m.searchByEcosystem(c.Ecosystem, c.PackageName, c.DistroType, c.DistroVersion)
	case *CPESearchCriteria:
		return m.searchByCPE(c.CPE)
	default:
		return nil, fmt.Errorf("unsupported search criteria type: %T", criteria)
	}
}

// searchByEcosystem searches vulnerabilities by ecosystem
func (m *BaseMatcher) searchByEcosystem(ecosystem, packageName, distroType, distroVersion string) ([]Vulnerability, error) {
	// This would interface with the actual vulnerability database
	// For now, we'll create a simplified implementation

	var dbVulns *[]model.Vulnerability

	// Use existing database methods
	switch ecosystem {
	case "npm":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "maven", "java":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "pypi", "python":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "rubygems", "gem":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "go":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "apk":
		dbVulns = m.store.ApkSecDBMatch(packageName)
	case "deb", "dpkg":
		// For Debian packages, we might need distro-specific matching
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	case "rpm":
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	default:
		dbVulns = m.store.NVDMatchWithKeywords([]string{packageName})
	}

	if dbVulns == nil {
		return []Vulnerability{}, nil
	}

	// Convert database vulnerabilities to matcher vulnerabilities
	var vulns []Vulnerability
	for _, dbVuln := range *dbVulns {
		vuln := Vulnerability{
			ID:                dbVuln.CVE,
			Namespace:         determineNamespace(ecosystem, distroType),
			PackageName:       packageName,
			VersionConstraint: dbVuln.Constraints,
			Fix: Fix{
				State:   determineFixState(dbVuln),
				Version: getFixedVersion(dbVuln),
			},
			Metadata: map[string]interface{}{
				"severity":    dbVuln.Severity,
				"cvss_score":  getCVSSScore(dbVuln),
				"description": dbVuln.Description,
				"source":      dbVuln.Source,
			},
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// searchByCPE searches vulnerabilities by CPE
func (m *BaseMatcher) searchByCPE(cpe string) ([]Vulnerability, error) {
	// This would search the database using CPE identifiers
	// For now, we'll return empty results as CPE matching is more complex
	return []Vulnerability{}, nil
}

// isVersionVulnerable checks if a package version is vulnerable based on constraints
func (m *BaseMatcher) isVersionVulnerable(version, constraint string) bool {
	if constraint == "" {
		return false
	}

	// This is a simplified version check
	// In practice, this would use proper version parsing and constraint checking
	// based on the package ecosystem's versioning scheme

	// For now, just check if the constraint is not empty
	return len(strings.TrimSpace(constraint)) > 0
}

// Helper functions

func determineNamespace(ecosystem, distroType string) string {
	if distroType != "" {
		return fmt.Sprintf("%s:distro:%s", ecosystem, distroType)
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
	case "apk":
		return "alpine:distro"
	case "deb", "dpkg":
		return "debian:distro"
	case "rpm":
		return "rhel:distro"
	default:
		return "nvd:cpe"
	}
}

func determineFixState(vuln model.Vulnerability) FixState {
	if len(vuln.Fixes) > 0 && vuln.Fixes[0] != "" {
		return matchertypes.FixStateFixed
	}
	return matchertypes.FixStateUnknown
}

// getFixedVersion extracts the fixed version from vulnerability data
func getFixedVersion(vuln model.Vulnerability) string {
	if len(vuln.Fixes) > 0 {
		return vuln.Fixes[0]
	}
	return ""
}

// getCVSSScore extracts CVSS score from vulnerability data
func getCVSSScore(vuln model.Vulnerability) float64 {
	if len(vuln.CVSS) > 0 {
		return vuln.CVSS[0].Score
	}
	return 0.0
}

// Search criteria implementations

// EcosystemSearchCriteria represents search by ecosystem and package name
type EcosystemSearchCriteria struct {
	Ecosystem     string
	PackageName   string
	DistroType    string
	DistroVersion string
}

func NewEcosystemSearchCriteria(ecosystem, packageName string) *EcosystemSearchCriteria {
	return &EcosystemSearchCriteria{
		Ecosystem:   ecosystem,
		PackageName: packageName,
	}
}

func (c *EcosystemSearchCriteria) WithDistro(distroType, distroVersion string) *EcosystemSearchCriteria {
	c.DistroType = distroType
	c.DistroVersion = distroVersion
	return c
}

func (c *EcosystemSearchCriteria) Apply(query *VulnerabilityQueryStruct) error {
	query.PackageName = c.PackageName
	query.DistroType = c.DistroType
	query.DistroVersion = c.DistroVersion
	return nil
}

// CPESearchCriteria represents search by CPE
type CPESearchCriteria struct {
	CPE string
}

func NewCPESearchCriteria(cpe string) *CPESearchCriteria {
	return &CPESearchCriteria{CPE: cpe}
}

func (c *CPESearchCriteria) Apply(query *VulnerabilityQueryStruct) error {
	query.CPE = c.CPE
	return nil
}
