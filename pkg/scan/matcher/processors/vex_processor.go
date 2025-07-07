package processors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// VEXProcessor handles Vulnerability Exploitability eXchange (VEX) documents
type VEXProcessor struct {
	documents []VEXDocument
	options   VEXProcessorOptions
}

// VEXProcessorOptions configures VEX processing behavior
type VEXProcessorOptions struct {
	DocumentPaths []string                  `json:"document_paths"`
	IgnoreRules   []matchertypes.IgnoreRule `json:"ignore_rules"`
	EnableLogging bool                      `json:"enable_logging"`
}

// VEXDocument represents a VEX document structure
type VEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Type       string         `json:"@type"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    string         `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement represents a VEX statement about a vulnerability
type VEXStatement struct {
	VulnerabilityID string                 `json:"vulnerability"`
	Timestamp       string                 `json:"timestamp"`
	Products        []VEXProduct           `json:"products"`
	Status          VEXStatus              `json:"status"`
	Justification   VEXJustification       `json:"justification,omitempty"`
	ImpactStatement string                 `json:"impact_statement,omitempty"`
	ActionStatement string                 `json:"action_statement,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// VEXProduct represents a product affected by a vulnerability
type VEXProduct struct {
	Component string                 `json:"@id"`
	Hashes    map[string]string      `json:"hashes,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// VEXStatus represents the status of a vulnerability for a product
type VEXStatus string

const (
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusFixed              VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// VEXJustification provides justification for VEX status
type VEXJustification string

const (
	VEXJustificationComponentNotPresent              VEXJustification = "component_not_present"
	VEXJustificationVulnerableCodeNotPresent         VEXJustification = "vulnerable_code_not_present"
	VEXJustificationVulnerableCodeCannotBeControlled VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	VEXJustificationVulnerableCodeNotInExecutePath   VEXJustification = "vulnerable_code_not_in_execute_path"
	VEXJustificationInlineMitigationsAlreadyExist    VEXJustification = "inline_mitigations_already_exist"
)

// NewVEXProcessor creates a new VEX processor
func NewVEXProcessor(options VEXProcessorOptions) (*VEXProcessor, error) {
	processor := &VEXProcessor{
		documents: make([]VEXDocument, 0),
		options:   options,
	}

	// Load VEX documents from specified paths
	for _, path := range options.DocumentPaths {
		if err := processor.loadDocument(path); err != nil {
			return nil, fmt.Errorf("failed to load VEX document from %s: %w", path, err)
		}
	}

	return processor, nil
}

// loadDocument loads a VEX document from a file path
func (p *VEXProcessor) loadDocument(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read VEX document: %w", err)
	}

	var doc VEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse VEX document: %w", err)
	}

	p.documents = append(p.documents, doc)
	return nil
}

// ApplyVEX processes matches against VEX documents and returns filtered results
func (p *VEXProcessor) ApplyVEX(ctx context.Context, matches []matchertypes.Match) ([]matchertypes.Match, []matchertypes.IgnoredMatch, error) {
	if len(p.documents) == 0 {
		return matches, []matchertypes.IgnoredMatch{}, nil
	}

	var filteredMatches []matchertypes.Match
	var ignoredMatches []matchertypes.IgnoredMatch

	for _, match := range matches {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		vexStatement := p.findVEXStatement(match.Vulnerability.ID, match.Package)
		if vexStatement == nil {
			// No VEX statement found, keep the match
			filteredMatches = append(filteredMatches, match)
			continue
		}

		switch vexStatement.Status {
		case VEXStatusNotAffected, VEXStatusFixed:
			// Convert match to ignored match
			ignoredMatch := matchertypes.IgnoredMatch{
				Match: match,
				AppliedIgnoreRules: []matchertypes.IgnoreRule{
					{
						Vulnerability: match.Vulnerability.ID,
					},
				},
			}
			ignoredMatches = append(ignoredMatches, ignoredMatch)

		case VEXStatusAffected, VEXStatusUnderInvestigation:
			// Keep the match but potentially adjust severity/metadata
			enhancedMatch := p.enhanceMatchWithVEX(match, vexStatement)
			filteredMatches = append(filteredMatches, enhancedMatch)

		default:
			// Unknown status, keep the match
			filteredMatches = append(filteredMatches, match)
		}
	}

	return filteredMatches, ignoredMatches, nil
}

// findVEXStatement finds a relevant VEX statement for a vulnerability and package
func (p *VEXProcessor) findVEXStatement(vulnerabilityID string, pkg matchertypes.Package) *VEXStatement {
	for _, doc := range p.documents {
		for _, statement := range doc.Statements {
			if p.matchesVulnerability(statement, vulnerabilityID) &&
				p.matchesProduct(statement, pkg) {
				return &statement
			}
		}
	}
	return nil
}

// matchesVulnerability checks if a VEX statement applies to a vulnerability
func (p *VEXProcessor) matchesVulnerability(statement VEXStatement, vulnerabilityID string) bool {
	// Direct ID match
	if statement.VulnerabilityID == vulnerabilityID {
		return true
	}

	// Handle different vulnerability ID formats (CVE, GHSA, etc.)
	return p.normalizeVulnerabilityID(statement.VulnerabilityID) ==
		p.normalizeVulnerabilityID(vulnerabilityID)
}

// matchesProduct checks if a VEX statement applies to a package/product
func (p *VEXProcessor) matchesProduct(statement VEXStatement, pkg matchertypes.Package) bool {
	for _, product := range statement.Products {
		if p.matchesPackage(product, pkg) {
			return true
		}
	}
	return false
}

// matchesPackage checks if a VEX product matches a package
func (p *VEXProcessor) matchesPackage(product VEXProduct, pkg matchertypes.Package) bool {
	// Simple component ID matching
	if product.Component == pkg.Name || product.Component == pkg.ID {
		return true
	}

	// Could be enhanced with more sophisticated matching based on:
	// - Package URLs (purl)
	// - CPEs
	// - Hashes
	// - Metadata

	return false
}

// enhanceMatchWithVEX enhances a match with VEX information
func (p *VEXProcessor) enhanceMatchWithVEX(match matchertypes.Match, statement *VEXStatement) matchertypes.Match {
	// Add VEX information to match metadata
	if match.Vulnerability.Metadata == nil {
		match.Vulnerability.Metadata = make(map[string]interface{})
	}

	match.Vulnerability.Metadata["vex_status"] = string(statement.Status)
	if statement.Justification != "" {
		match.Vulnerability.Metadata["vex_justification"] = string(statement.Justification)
	}
	if statement.ImpactStatement != "" {
		match.Vulnerability.Metadata["vex_impact_statement"] = statement.ImpactStatement
	}
	if statement.ActionStatement != "" {
		match.Vulnerability.Metadata["vex_action_statement"] = statement.ActionStatement
	}

	return match
}

// normalizeVulnerabilityID normalizes vulnerability IDs for comparison
func (p *VEXProcessor) normalizeVulnerabilityID(id string) string {
	// Handle different vulnerability ID formats
	// e.g., CVE-2021-1234, GHSA-xxxx-xxxx-xxxx
	return id // Simplified for now
}

// GetLoadedDocuments returns information about loaded VEX documents
func (p *VEXProcessor) GetLoadedDocuments() []VEXDocumentInfo {
	var info []VEXDocumentInfo
	for _, doc := range p.documents {
		info = append(info, VEXDocumentInfo{
			ID:             doc.ID,
			Author:         doc.Author,
			Version:        doc.Version,
			Timestamp:      doc.Timestamp,
			StatementCount: len(doc.Statements),
		})
	}
	return info
}

// VEXDocumentInfo provides summary information about a VEX document
type VEXDocumentInfo struct {
	ID             string `json:"id"`
	Author         string `json:"author"`
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
	StatementCount int    `json:"statement_count"`
}
