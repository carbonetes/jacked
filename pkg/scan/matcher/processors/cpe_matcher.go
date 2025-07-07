package processors

import (
	"context"
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// CPEMatcher provides CPE-based vulnerability matching similar to Grype's approach
type CPEMatcher struct {
	baseType  matchertypes.MatcherType
	useCPEs   bool
	provider  VulnerabilityProvider
	cpeParser CPEParser
}

// CPEParser defines interface for parsing and working with CPE strings
type CPEParser interface {
	Parse(cpe string) (*CPE, error)
	GenerateCPEs(pkg matchertypes.Package) ([]string, error)
}

// CPE represents a parsed Common Platform Enumeration
type CPE struct {
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SwEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

// VulnerabilityProvider defines interface for retrieving vulnerabilities
type VulnerabilityProvider interface {
	FindVulnerabilitiesByCPE(cpe string) ([]matchertypes.Vulnerability, error)
	FindVulnerabilitiesByEcosystem(ecosystem, name string) ([]matchertypes.Vulnerability, error)
	PackageSearchNames(pkg matchertypes.Package) []string
}

// NewCPEMatcher creates a new CPE-based vulnerability matcher
func NewCPEMatcher(baseType matchertypes.MatcherType, provider VulnerabilityProvider, parser CPEParser) *CPEMatcher {
	return &CPEMatcher{
		baseType:  baseType,
		useCPEs:   true,
		provider:  provider,
		cpeParser: parser,
	}
}

// Type returns the matcher type
func (m *CPEMatcher) Type() matchertypes.MatcherType {
	return m.baseType
}

// FindMatches performs CPE-based vulnerability matching
func (m *CPEMatcher) FindMatches(ctx context.Context, packages []matchertypes.Package, opts matchertypes.MatchOptions) (*matchertypes.MatchResults, error) {
	var allMatches []matchertypes.Match

	for _, pkg := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Try ecosystem-based matching first
		ecosystemMatches, err := m.findEcosystemMatches(pkg)
		if err != nil {
			return nil, fmt.Errorf("ecosystem matching failed for %s: %w", pkg.Name, err)
		}
		allMatches = append(allMatches, ecosystemMatches...)

		// If CPE matching is enabled, also try CPE-based matching
		if m.useCPEs || opts.CPEMatching {
			cpeMatches, err := m.findCPEMatches(pkg)
			if err != nil {
				return nil, fmt.Errorf("CPE matching failed for %s: %w", pkg.Name, err)
			}
			allMatches = append(allMatches, cpeMatches...)
		}
	}

	return &matchertypes.MatchResults{
		Matches: allMatches,
		Summary: matchertypes.MatchSummary{
			TotalPackages: len(packages),
			TotalMatches:  len(allMatches),
		},
	}, nil
}

// findEcosystemMatches performs ecosystem-specific vulnerability matching
func (m *CPEMatcher) findEcosystemMatches(pkg matchertypes.Package) ([]matchertypes.Match, error) {
	var matches []matchertypes.Match

	// Get search names for this package
	searchNames := m.provider.PackageSearchNames(pkg)

	for _, name := range searchNames {
		vulns, err := m.provider.FindVulnerabilitiesByEcosystem(pkg.Ecosystem, name)
		if err != nil {
			continue // Log error but continue with other names
		}

		for _, vuln := range vulns {
			// Check if vulnerability applies to this package version
			if m.isVersionVulnerable(pkg.Version, vuln.VersionConstraint) {
				match := matchertypes.Match{
					Vulnerability: vuln,
					Package:       pkg,
					Details: []matchertypes.MatchDetail{
						{
							Type:       matchertypes.ExactDirectMatch,
							Confidence: 1.0,
							Matcher:    string(m.baseType),
							SearchedBy: map[string]interface{}{
								"ecosystem": pkg.Ecosystem,
								"name":      name,
								"version":   pkg.Version,
							},
							Found: map[string]interface{}{
								"vulnerabilityID":   vuln.ID,
								"versionConstraint": vuln.VersionConstraint,
								"matchStrategy":     "ecosystem",
							},
						},
					},
				}
				matches = append(matches, match)
			}
		}
	}

	return matches, nil
}

// findCPEMatches performs CPE-based vulnerability matching
func (m *CPEMatcher) findCPEMatches(pkg matchertypes.Package) ([]matchertypes.Match, error) {
	var matches []matchertypes.Match

	cpes := m.getCPEsForPackage(pkg)

	for _, cpeStr := range cpes {
		cpeMatches, err := m.processSingleCPE(pkg, cpeStr)
		if err != nil {
			continue // Log error but continue with other CPEs
		}
		matches = append(matches, cpeMatches...)
	}

	return matches, nil
}

// getCPEsForPackage gets or generates CPEs for a package
func (m *CPEMatcher) getCPEsForPackage(pkg matchertypes.Package) []string {
	if len(pkg.CPEs) > 0 {
		return pkg.CPEs
	}

	// Generate CPEs if none exist
	generatedCPEs, err := m.cpeParser.GenerateCPEs(pkg)
	if err != nil {
		return []string{} // Return empty if generation fails
	}
	return generatedCPEs
}

// processSingleCPE processes vulnerabilities for a single CPE
func (m *CPEMatcher) processSingleCPE(pkg matchertypes.Package, cpeStr string) ([]matchertypes.Match, error) {
	var matches []matchertypes.Match

	vulns, err := m.provider.FindVulnerabilitiesByCPE(cpeStr)
	if err != nil {
		return matches, err
	}

	cpe, err := m.cpeParser.Parse(cpeStr)
	if err != nil {
		return matches, err // Skip invalid CPEs
	}

	for _, vuln := range vulns {
		if m.isValidMatch(pkg, vuln, cpe) {
			match := m.createCPEMatch(pkg, vuln, cpeStr)
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// isValidMatch checks if a vulnerability is a valid match for the package
func (m *CPEMatcher) isValidMatch(pkg matchertypes.Package, vuln matchertypes.Vulnerability, cpe *CPE) bool {
	return m.isVulnerableTarget(pkg, vuln, cpe) &&
		m.isVersionVulnerable(pkg.Version, vuln.VersionConstraint)
}

// createCPEMatch creates a match object for a CPE-based match
func (m *CPEMatcher) createCPEMatch(pkg matchertypes.Package, vuln matchertypes.Vulnerability, cpeStr string) matchertypes.Match {
	return matchertypes.Match{
		Vulnerability: vuln,
		Package:       pkg,
		Details: []matchertypes.MatchDetail{
			{
				Type:       matchertypes.CPEMatch,
				Confidence: 0.9, // Slightly lower confidence for CPE matches
				Matcher:    string(m.baseType),
				SearchedBy: map[string]interface{}{
					"cpe":       cpeStr,
					"namespace": vuln.Namespace,
				},
				Found: map[string]interface{}{
					"vulnerabilityID":   vuln.ID,
					"versionConstraint": vuln.VersionConstraint,
					"matchStrategy":     "cpe",
				},
			},
		},
	}
}

// isVulnerableTarget checks if a vulnerability applies to a specific package type/target
func (m *CPEMatcher) isVulnerableTarget(pkg matchertypes.Package, vuln matchertypes.Vulnerability, packageCPE *CPE) bool {
	// If vulnerability has no CPEs, assume it applies
	if len(vuln.CPEs) == 0 {
		return true
	}

	// For OS packages, always consider vulnerable (they can embed any ecosystem)
	if m.isOSPackage(pkg) {
		return true
	}

	// For binary and unknown packages, use strict CPE filtering
	if pkg.Type == matchertypes.BinaryPkg || pkg.Type == matchertypes.UnknownPkg {
		return m.hasMatchingTargetSoftware(packageCPE, vuln.CPEs)
	}

	// For Java packages, be more permissive (can embed JS packages)
	if pkg.Language == matchertypes.Java {
		return true
	}

	// Check if target software aligns with package ecosystem
	return m.hasMatchingTargetSoftware(packageCPE, vuln.CPEs)
}

// isOSPackage checks if a package is an OS-level package
func (m *CPEMatcher) isOSPackage(pkg matchertypes.Package) bool {
	return pkg.Type == matchertypes.DebPkg ||
		pkg.Type == matchertypes.RPMPkg ||
		pkg.Type == matchertypes.APKPkg
}

// hasMatchingTargetSoftware checks if package and vulnerability CPEs have compatible target software
func (m *CPEMatcher) hasMatchingTargetSoftware(packageCPE *CPE, vulnCPEs []string) bool {
	if packageCPE.TargetSW == "*" || packageCPE.TargetSW == "" {
		return true
	}

	for _, vulnCPEStr := range vulnCPEs {
		vulnCPE, err := m.cpeParser.Parse(vulnCPEStr)
		if err != nil {
			continue
		}

		if vulnCPE.TargetSW == "*" || vulnCPE.TargetSW == "" {
			return true
		}

		if packageCPE.TargetSW == vulnCPE.TargetSW {
			return true
		}
	}

	return false
}

// isVersionVulnerable checks if a package version satisfies a vulnerability constraint
func (m *CPEMatcher) isVersionVulnerable(version, constraint string) bool {
	// This is a simplified version check - in practice you'd use a proper version
	// comparison library that understands different version formats
	if constraint == "" || constraint == "*" {
		return true
	}

	// Handle common constraint patterns
	if strings.HasPrefix(constraint, "<") {
		// Version range checking would go here
		return true // Simplified for demo
	}

	if strings.HasPrefix(constraint, ">=") && strings.Contains(constraint, "<") {
		// Range checking would go here
		return true // Simplified for demo
	}

	return version == constraint
}
