package base

import (
	"context"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/pkg/model"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
)

// ComponentScanner provides a base implementation for component-specific scanners
type ComponentScanner struct {
	scannerType   string
	componentType string
	store         db.Store
	versionParser VersionParser
}

// VersionParser defines interface for parsing and checking versions
type VersionParser interface {
	Parse(version string) (VersionChecker, error)
}

// VersionChecker defines interface for version constraint checking
type VersionChecker interface {
	Check(constraint string) (bool, error)
}

// NewComponentScanner creates a new base component scanner
func NewComponentScanner(scannerType, componentType string, store db.Store, parser VersionParser) *ComponentScanner {
	return &ComponentScanner{
		scannerType:   scannerType,
		componentType: componentType,
		store:         store,
		versionParser: parser,
	}
}

// Type returns the scanner type identifier
func (s *ComponentScanner) Type() string {
	return s.scannerType
}

// SupportsComponent checks if scanner can handle a component type
func (s *ComponentScanner) SupportsComponent(componentType string) bool {
	return componentType == s.componentType
}

// Scan processes a BOM and returns vulnerabilities for supported components
func (s *ComponentScanner) Scan(ctx context.Context, bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var results []cyclonedx.Vulnerability

	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	for _, component := range *bom.Components {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Skip components that this scanner doesn't support
		if !s.isRelevantComponent(component) {
			continue
		}

		// Process the component
		componentVulns, err := s.processComponent(component)
		if err != nil {
			return nil, fmt.Errorf("failed to process component %s: %w", component.Name, err)
		}

		results = append(results, componentVulns...)
	}

	return results, nil
}

// isRelevantComponent checks if a component is relevant for this scanner
func (s *ComponentScanner) isRelevantComponent(component cyclonedx.Component) bool {
	if component.Properties == nil {
		return false
	}

	componentType := helper.GetComponentType(component.Properties)
	return componentType == s.componentType
}

// processComponent processes a single component and returns its vulnerabilities
func (s *ComponentScanner) processComponent(component cyclonedx.Component) ([]cyclonedx.Vulnerability, error) {
	// Get vulnerability data for the component
	vulns := s.getVulnerabilities(component)
	if vulns == nil {
		return []cyclonedx.Vulnerability{}, nil
	}

	// Parse component version
	versionChecker, err := s.versionParser.Parse(component.Version)
	if err != nil {
		// Log error but don't fail - version parsing issues are common
		return []cyclonedx.Vulnerability{}, nil
	}

	var results []cyclonedx.Vulnerability
	for _, vuln := range *vulns {
		if vuln.Constraints == "" {
			continue
		}

		// Check if vulnerability applies to this version
		match, err := versionChecker.Check(vuln.Constraints)
		if err != nil {
			// Log error but continue with other vulnerabilities
			continue
		}

		if match {
			// Convert to CycloneDX vulnerability format
			vex := v3.ToVex(&vuln, &component, vuln.Constraints)
			if vex != nil {
				results = append(results, *vex)
			}
		}
	}

	return results, nil
}

// getVulnerabilities retrieves vulnerabilities for a component (to be overridden by specific scanners)
func (s *ComponentScanner) getVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	// Default implementation - try NVD match with keywords
	upstream := helper.FindUpstream(component.BOMRef)
	keywords := []string{component.Name}
	if upstream != "" {
		keywords = append(keywords, upstream)
	}

	return s.store.NVDMatchWithKeywords(keywords)
}

// VulnerabilityProvider defines interface for getting vulnerabilities for specific scanner types
type VulnerabilityProvider interface {
	GetVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability
}

// CustomComponentScanner allows for custom vulnerability retrieval logic
type CustomComponentScanner struct {
	*ComponentScanner
	provider VulnerabilityProvider
}

// NewCustomComponentScanner creates a scanner with custom vulnerability provider
func NewCustomComponentScanner(scannerType, componentType string, store db.Store, parser VersionParser, provider VulnerabilityProvider) *CustomComponentScanner {
	return &CustomComponentScanner{
		ComponentScanner: NewComponentScanner(scannerType, componentType, store, parser),
		provider:         provider,
	}
}

// getVulnerabilities uses the custom provider
func (s *CustomComponentScanner) getVulnerabilities(component cyclonedx.Component) *[]model.Vulnerability {
	return s.provider.GetVulnerabilities(component)
}
