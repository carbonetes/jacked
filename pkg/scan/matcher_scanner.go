package scan

import (
	"context"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/model"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/scan/matcher"
	"github.com/carbonetes/jacked/pkg/scan/matcher/dart"
	"github.com/carbonetes/jacked/pkg/scan/matcher/golang"
	"github.com/carbonetes/jacked/pkg/scan/matcher/maven"
	"github.com/carbonetes/jacked/pkg/scan/matcher/npm"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/apk"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/dpkg"
	"github.com/carbonetes/jacked/pkg/scan/matcher/os/rpm"
	"github.com/carbonetes/jacked/pkg/scan/matcher/python"
	"github.com/carbonetes/jacked/pkg/scan/matcher/ruby"
	"github.com/carbonetes/jacked/pkg/scan/matcher/stock"
	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// MatcherScanner implements the core.Scanner interface using the new matcher engine
type MatcherScanner struct {
	engine          *matcher.Engine
	config          matchertypes.MatcherConfig
	store           db.Store            // Add store for vulnerability enrichment
	extendedMatcher *MatcherIntegration // Optional extended matcher
	useExtendedMode bool                // Flag to enable extended matching
}

// StoreVulnerabilityProvider adapts the db.Store to the VulnerabilityProvider interface
type StoreVulnerabilityProvider struct {
	store db.Store
}

// FindVulnerabilities searches for vulnerabilities based on search criteria
func (p *StoreVulnerabilityProvider) FindVulnerabilities(ctx context.Context, searchBy ...interface{}) ([]matchertypes.Vulnerability, error) {
	// This is a simplified implementation - in a real scenario, we would
	// need to implement proper search criteria handling
	return []matchertypes.Vulnerability{}, nil
}

// GetVulnerabilityMetadata gets metadata for a specific vulnerability
func (p *StoreVulnerabilityProvider) GetVulnerabilityMetadata(ctx context.Context, id, namespace string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

// Close closes the provider and releases resources
func (p *StoreVulnerabilityProvider) Close() error {
	return nil
}

// NewMatcherScanner creates a new scanner that uses the matcher engine
func NewMatcherScanner(store db.Store, config *matchertypes.MatcherConfig) *MatcherScanner {
	return NewMatcherScannerWithConfig(store, config)
}

// NewMatcherScannerWithConfig creates a scanner with custom matching configuration
func NewMatcherScannerWithConfig(store db.Store, config *matchertypes.MatcherConfig) *MatcherScanner {
	// Use default config if none provided
	if config == nil {
		config = &matchertypes.MatcherConfig{
			UseCPEs:            true,
			MaxConcurrency:     4,
			Timeout:            "5m",
			EnableCaching:      true,
			EnableMetrics:      false,
			NormalizeByCVE:     true,
			CPEMatching:        true,
			DeduplicateResults: true,
			DefaultIgnoreRules: []matchertypes.IgnoreRule{},
		}
	}

	// Create a vulnerability provider that can interface with the store
	provider := &StoreVulnerabilityProvider{store: store}
	_ = provider // Will be used when provider support is fully implemented
	engine := matcher.NewEngine(*config)

	// Register all available matchers
	engine.RegisterMatcher(npm.NewMatcher(store))
	engine.RegisterMatcher(python.NewMatcher(store))
	engine.RegisterMatcher(maven.NewMatcher(store))
	engine.RegisterMatcher(golang.NewMatcher(store))
	engine.RegisterMatcher(ruby.NewMatcher(store))
	engine.RegisterMatcher(dart.NewMatcher(store))
	engine.RegisterMatcher(stock.NewMatcher(store))

	// Register OS-specific matchers
	engine.RegisterMatcher(apk.NewMatcher(store))
	engine.RegisterMatcher(dpkg.NewMatcher(store))
	engine.RegisterMatcher(rpm.NewMatcher(store))

	scanner := &MatcherScanner{
		engine:          engine,
		config:          *config,
		store:           store,
		useExtendedMode: false,
	}

	return scanner
}

// Type returns the scanner type identifier
func (s *MatcherScanner) Type() string {
	return "matcher"
}

// SupportsComponent checks if scanner can handle any component type
// The matcher scanner is designed to handle all component types through its matchers
func (s *MatcherScanner) SupportsComponent(componentType string) bool {
	// The matcher scanner supports all component types since it has ecosystem-specific matchers
	return true
}

// Scan processes a BOM and returns vulnerabilities using the matcher engine
func (s *MatcherScanner) Scan(ctx context.Context, bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return []cyclonedx.Vulnerability{}, nil
	}

	log.Debugf("Matcher scanner processing %d components", len(*bom.Components))

	// Convert BOM components to matcher packages
	packages := s.convertBOMToPackages(bom)
	if len(packages) == 0 {
		log.Debug("No valid packages found for matching")
		return []cyclonedx.Vulnerability{}, nil
	}

	var results *matcher.MatchResults
	var err error

	if s.useExtendedMode && s.extendedMatcher != nil {
		// Use extended matcher
		log.Debug("Using extended vulnerability matching")

		// Configure extended match options
		extendedOpts := matchertypes.MatchOptions{
			IgnoreRules:         s.config.DefaultIgnoreRules,
			NormalizeByCVE:      s.config.NormalizeByCVE,
			CPEMatching:         s.config.CPEMatching,
			MaxConcurrency:      s.config.MaxConcurrency,
			Timeout:             s.config.Timeout,
			EnableProgressTrack: true,
			DeduplicateResults:  s.config.DeduplicateResults,
		}

		// Run extended matcher
		extendedResults, err := s.extendedMatcher.GetExtendedMatcher().FindMatches(ctx, packages, extendedOpts)
		if err != nil {
			log.Warnf("Extended matcher failed, falling back to standard matcher: %v", err)
			// Fall back to standard matcher
			if results, err = s.engine.FindMatches(ctx, packages, s.getStandardMatchOptions()); err != nil {
				return nil, err
			}
		} else {
			// Convert extended results to standard results format
			results = s.convertExtendedResults(extendedResults)
		}
	} else {
		// Use standard matcher
		log.Debug("Using standard vulnerability matching")
		results, err = s.engine.FindMatches(ctx, packages, s.getStandardMatchOptions())
	}

	if err != nil {
		return nil, err
	}

	// Convert matches back to CycloneDX vulnerabilities
	vulnerabilities := s.convertMatchesToVulnerabilities(results.Matches, bom)

	log.Debugf("Matcher scanner found %d vulnerabilities", len(vulnerabilities))
	return vulnerabilities, nil
}

// getStandardMatchOptions returns standard match options
func (s *MatcherScanner) getStandardMatchOptions() matcher.MatchOptions {
	return matcher.MatchOptions{
		IgnoreRules:         s.config.DefaultIgnoreRules,
		NormalizeByCVE:      s.config.NormalizeByCVE,
		CPEMatching:         s.config.CPEMatching,
		MaxConcurrency:      s.config.MaxConcurrency,
		Timeout:             s.config.Timeout,
		EnableProgressTrack: true,
		DeduplicateResults:  s.config.DeduplicateResults,
	}
}

// convertExtendedResults converts advanced match results to standard format
func (s *MatcherScanner) convertExtendedResults(extendedResults *matchertypes.MatchResults) *matcher.MatchResults {
	return &matcher.MatchResults{
		Matches:        extendedResults.Matches,
		IgnoredMatches: extendedResults.IgnoredMatches,
		Summary:        extendedResults.Summary,
	}
}

// convertBOMToPackages converts CycloneDX BOM components to matcher packages
func (s *MatcherScanner) convertBOMToPackages(bom *cyclonedx.BOM) []matcher.Package {
	var packages []matcher.Package

	for _, component := range *bom.Components {
		pkg := matcher.Package{
			ID:        component.BOMRef,
			Name:      component.Name,
			Version:   component.Version,
			Type:      s.getPackageType(component),
			Language:  s.getLanguage(component),
			Ecosystem: s.getEcosystem(component),
			CPEs:      s.extractCPEs(component),
			Metadata: map[string]any{
				"component": component,
				"bomRef":    component.BOMRef,
			},
		}

		packages = append(packages, pkg)
	}

	return packages
}

// getPackageType extracts the package type from a CycloneDX component
func (s *MatcherScanner) getPackageType(component cyclonedx.Component) matchertypes.PackageType {
	componentType := s.getComponentType(component)

	switch componentType {
	case "npm":
		return matchertypes.NPMPkg
	case "go", "golang":
		return matchertypes.GoPkg
	case "java", "maven":
		return matchertypes.JavaPkg
	case "python", "pypi":
		return matchertypes.PythonPkg
	case "gem", "rubygem":
		return matchertypes.GemPkg
	case "apk":
		return matchertypes.APKPkg
	case "deb", "dpkg":
		return matchertypes.DebPkg
	case "rpm":
		return matchertypes.RPMPkg
	default:
		return matchertypes.UnknownPkg
	}
}

// getLanguage extracts the programming language from a CycloneDX component
func (s *MatcherScanner) getLanguage(component cyclonedx.Component) matchertypes.Language {
	componentType := s.getComponentType(component)

	switch componentType {
	case "npm":
		return matchertypes.JavaScript
	case "go", "golang":
		return matchertypes.Go
	case "java", "maven":
		return matchertypes.Java
	case "python", "pypi":
		return matchertypes.Python
	case "gem", "rubygem":
		return matchertypes.Ruby
	default:
		return matchertypes.UnknownLang
	}
}

// getEcosystem extracts the ecosystem from a CycloneDX component
func (s *MatcherScanner) getEcosystem(component cyclonedx.Component) string {
	return s.getComponentType(component)
}

// getComponentType extracts the component type from a CycloneDX component
func (s *MatcherScanner) getComponentType(component cyclonedx.Component) string {
	// First check properties for diggity:package:type (this is what diggity sets)
	if componentType := s.getTypeFromProperties(component); componentType != "" {
		return componentType
	}

	// Check if we can extract type from PURL
	if componentType := s.getTypeFromPURL(component); componentType != "" {
		return componentType
	}

	// Fallback to component type field if available
	if component.Type != "" {
		return string(component.Type)
	}

	return "unknown"
}

// getTypeFromProperties extracts component type from properties
func (s *MatcherScanner) getTypeFromProperties(component cyclonedx.Component) string {
	if component.Properties == nil {
		return ""
	}

	for _, prop := range *component.Properties {
		if prop.Name == "diggity:package:type" || prop.Name == "component:type" {
			return prop.Value
		}
	}

	return ""
}

// getTypeFromPURL extracts component type from PURL
func (s *MatcherScanner) getTypeFromPURL(component cyclonedx.Component) string {
	if component.BOMRef == "" || !strings.HasPrefix(component.BOMRef, "pkg:") {
		return ""
	}

	// Extract ecosystem from PURL (e.g., "pkg:apk/package@version" -> "apk")
	parts := strings.Split(component.BOMRef, "/")
	if len(parts) > 0 {
		typeWithPkg := parts[0]
		if strings.HasPrefix(typeWithPkg, "pkg:") {
			return strings.TrimPrefix(typeWithPkg, "pkg:")
		}
	}

	return ""
}

// extractCPEs extracts CPE strings from a CycloneDX component
func (s *MatcherScanner) extractCPEs(component cyclonedx.Component) []string {
	var cpes []string

	// Check if component has CPE property
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "cpe" || prop.Name == "cpe23" {
				cpes = append(cpes, prop.Value)
			}
		}
	}

	// Check component CPE field if available (depends on CycloneDX version)
	if component.CPE != "" {
		cpes = append(cpes, component.CPE)
	}

	return cpes
}

// convertMatchesToVulnerabilities converts matcher results to CycloneDX vulnerabilities
func (s *MatcherScanner) convertMatchesToVulnerabilities(matches []matcher.Match, bom *cyclonedx.BOM) []cyclonedx.Vulnerability {
	var vulnerabilities []cyclonedx.Vulnerability

	for _, match := range matches {
		// Extract the original component from metadata
		componentInterface, ok := match.Package.Metadata["component"]
		if !ok {
			continue
		}

		component, ok := componentInterface.(cyclonedx.Component)
		if !ok {
			continue
		}

		// Convert the match to a CycloneDX vulnerability
		vuln := s.matchToVulnerability(match, component)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}
	}

	return vulnerabilities
}

// matchToVulnerability converts a single match to a CycloneDX vulnerability using VEX mapping
func (s *MatcherScanner) matchToVulnerability(match matcher.Match, component cyclonedx.Component) *cyclonedx.Vulnerability {
	// Convert the matcher vulnerability to our internal vulnerability type
	dbVuln := s.convertMatcherVulnToDBVuln(match.Vulnerability, component)

	// Use the VEX mapping to create a proper CycloneDX vulnerability
	vex := v3.ToVex(&dbVuln, &component, match.Vulnerability.VersionConstraint)
	if vex == nil {
		return nil
	}

	// Enrich with additional data from the database if available
	s.enrichVulnerabilityDataFromDB(vex, match.Vulnerability)

	return vex
}

// convertMatcherVulnToDBVuln converts a matcher vulnerability to internal vulnerability type
func (s *MatcherScanner) convertMatcherVulnToDBVuln(matcherVuln matchertypes.Vulnerability, component cyclonedx.Component) model.Vulnerability {
	dbVuln := model.Vulnerability{
		Package:     matcherVuln.PackageName,
		Constraints: matcherVuln.VersionConstraint,
		Source:      matcherVuln.Namespace,
		CPE:         matcherVuln.CPEs,
	}

	// Enrich with database data
	s.enrichFromDatabase(&dbVuln, matcherVuln.ID)

	// Enrich with matcher data if database data is missing
	s.enrichFromMatcher(&dbVuln, matcherVuln)

	return dbVuln
}

// enrichFromDatabase enriches vulnerability with database data
func (s *MatcherScanner) enrichFromDatabase(dbVuln *model.Vulnerability, matcherID string) {
	if dbRecord, err := s.store.GetVulnerabilityByID(matcherID); err == nil && dbRecord != nil {
		// Use actual CVE from database, not database ID
		dbVuln.CVE = s.getActualCVE(dbRecord, matcherID)

		// Get severity from CVSS data if available, otherwise use database severity
		dbVuln.Severity = s.extractSeverityFromCVSS(dbRecord)

		dbVuln.Description = dbRecord.Description
		dbVuln.References = dbRecord.References
		dbVuln.Fixes = dbRecord.Fixes
		dbVuln.CVSS = dbRecord.CVSS
	} else {
		// Fallback to matcher ID if database lookup fails
		dbVuln.CVE = matcherID
		dbVuln.Severity = "unknown"
	}
}

// extractSeverityFromCVSS extracts severity from CVSS data or falls back to database severity
func (s *MatcherScanner) extractSeverityFromCVSS(dbRecord *model.Vulnerability) string {
	// First check CVSS data for severity
	if len(dbRecord.CVSS) > 0 {
		for _, cvss := range dbRecord.CVSS {
			if cvss.Severity != "" {
				return strings.ToLower(cvss.Severity)
			}
		}
	}

	// Fall back to database severity field if no CVSS severity
	if dbRecord.Severity != "" && dbRecord.Severity != "unknown" {
		return strings.ToLower(dbRecord.Severity)
	}

	// If no valid severity data, return unknown
	return "unknown"
}

// getActualCVE returns the actual CVE or falls back to the ID
func (s *MatcherScanner) getActualCVE(dbRecord *model.Vulnerability, fallbackID string) string {
	if dbRecord.CVE != "" {
		return dbRecord.CVE
	}
	return fallbackID
}

// enrichFromMatcher enriches vulnerability with matcher data for missing fields
func (s *MatcherScanner) enrichFromMatcher(dbVuln *model.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	// Extract description from advisories if not already set
	if dbVuln.Description == "" {
		s.extractDescriptionFromAdvisories(dbVuln, matcherVuln)
	}

	// Extract severity from metadata if not already set
	if dbVuln.Severity == "" {
		s.extractSeverityFromMetadata(dbVuln, matcherVuln)
	}

	// Extract fix information if not already set
	if len(dbVuln.Fixes) == 0 {
		s.extractFixFromMatcher(dbVuln, matcherVuln)
	}

	// Build references from advisories if not already set
	if len(dbVuln.References) == 0 {
		s.extractReferencesFromAdvisories(dbVuln, matcherVuln)
	}
}

// extractDescriptionFromAdvisories extracts description from matcher advisories
func (s *MatcherScanner) extractDescriptionFromAdvisories(dbVuln *model.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	if len(matcherVuln.Advisories) > 0 && matcherVuln.Advisories[0].Description != "" {
		dbVuln.Description = matcherVuln.Advisories[0].Description
	}
}

// extractSeverityFromMetadata extracts severity from matcher metadata
func (s *MatcherScanner) extractSeverityFromMetadata(dbVuln *model.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	if severity, exists := matcherVuln.Metadata["severity"]; exists {
		if severityStr, ok := severity.(string); ok {
			dbVuln.Severity = severityStr
		}
	}
}

// extractFixFromMatcher extracts fix information from matcher
func (s *MatcherScanner) extractFixFromMatcher(dbVuln *model.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	if matcherVuln.Fix.State == matchertypes.FixStateFixed && matcherVuln.Fix.Version != "" {
		dbVuln.Fixes = []string{matcherVuln.Fix.Version}
	}
}

// extractReferencesFromAdvisories extracts references from matcher advisories
func (s *MatcherScanner) extractReferencesFromAdvisories(dbVuln *model.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	for _, advisory := range matcherVuln.Advisories {
		if advisory.Link != "" {
			dbVuln.References = append(dbVuln.References, model.Reference{
				URL:    advisory.Link,
				Source: advisory.ID,
			})
		}
	}
}

const vulnerabilityDatabaseSource = "vulnerability-database"

// enrichVulnerabilityDataFromDB enriches VEX data with additional database information
func (s *MatcherScanner) enrichVulnerabilityDataFromDB(vex *cyclonedx.Vulnerability, matcherVuln matchertypes.Vulnerability) {
	// Try to get additional data from database
	if dbVuln, err := s.store.GetVulnerabilityByID(matcherVuln.ID); err == nil && dbVuln != nil {
		s.enhanceDescription(vex, dbVuln)
		s.enhanceSeverity(vex, dbVuln)
		s.addAdditionalReferences(vex, dbVuln)
	}
}

// enhanceDescription updates the description if empty or generic
func (s *MatcherScanner) enhanceDescription(vex *cyclonedx.Vulnerability, dbVuln *model.Vulnerability) {
	if vex.Description == "" || vex.Description == "Alpine security advisory - details available online" {
		if dbVuln.Description != "" {
			vex.Description = dbVuln.Description
		}
	}
}

// enhanceSeverity updates the severity if not set or unknown
func (s *MatcherScanner) enhanceSeverity(vex *cyclonedx.Vulnerability, dbVuln *model.Vulnerability) {
	if vex.Ratings == nil || len(*vex.Ratings) == 0 || (*vex.Ratings)[0].Severity == "" {
		if dbVuln.Severity != "" && dbVuln.Severity != "unknown" {
			rating := cyclonedx.VulnerabilityRating{
				Source:   &cyclonedx.Source{Name: vulnerabilityDatabaseSource},
				Severity: cyclonedx.Severity(strings.ToUpper(dbVuln.Severity)),
			}
			vex.Ratings = &[]cyclonedx.VulnerabilityRating{rating}
		}
	}
}

// addAdditionalReferences adds database references to the VEX
func (s *MatcherScanner) addAdditionalReferences(vex *cyclonedx.Vulnerability, dbVuln *model.Vulnerability) {
	if len(dbVuln.References) > 0 && vex.References != nil {
		for _, ref := range dbVuln.References {
			*vex.References = append(*vex.References, cyclonedx.VulnerabilityReference{
				ID: vex.ID,
				Source: &cyclonedx.Source{
					Name: ref.Source,
					URL:  ref.URL,
				},
			})
		}
	}
}
