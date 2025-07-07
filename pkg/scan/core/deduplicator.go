package core

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// SmartDeduplicator provides enhanced vulnerability deduplication
type SmartDeduplicator struct {
	// Configuration options can be added here
}

// NewSmartDeduplicator creates a new smart deduplicator
func NewSmartDeduplicator() *SmartDeduplicator {
	return &SmartDeduplicator{}
}

// Deduplicate removes duplicate vulnerabilities using multiple criteria
func (d *SmartDeduplicator) Deduplicate(vulnerabilities []cyclonedx.Vulnerability) []cyclonedx.Vulnerability {
	if len(vulnerabilities) == 0 {
		return vulnerabilities
	}

	vulnMap := make(map[string]cyclonedx.Vulnerability)

	for _, vuln := range vulnerabilities {
		key := d.createDeduplicationKey(vuln)

		if existing, exists := vulnMap[key]; exists {
			// Keep the vulnerability with more complete information
			if d.isMoreComplete(vuln, existing) {
				vulnMap[key] = vuln
			}
		} else {
			vulnMap[key] = vuln
		}
	}

	// Convert back to slice
	result := make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		result = append(result, vuln)
	}

	return result
}

// createDeduplicationKey creates a comprehensive key for vulnerability identification
func (d *SmartDeduplicator) createDeduplicationKey(vuln cyclonedx.Vulnerability) string {
	// Primary key components
	key := fmt.Sprintf("%s|%s", vuln.BOMRef, vuln.ID)

	// Include source information if available
	if vuln.Properties != nil {
		for _, prop := range *vuln.Properties {
			if prop.Name == "database:source" || prop.Name == "source" {
				key += "|" + prop.Value
				break
			}
		}
	}

	// Include affected component information for more precision
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		affects := *vuln.Affects
		if len(affects) > 0 && affects[0].Ref != "" {
			key += "|" + affects[0].Ref
		}
	}

	return key
}

// isMoreComplete determines which vulnerability has more complete information
func (d *SmartDeduplicator) isMoreComplete(vuln1, vuln2 cyclonedx.Vulnerability) bool {
	score1 := d.calculateCompletenessScore(vuln1)
	score2 := d.calculateCompletenessScore(vuln2)
	return score1 > score2
}

// calculateCompletenessScore assigns a score based on vulnerability completeness
func (d *SmartDeduplicator) calculateCompletenessScore(vuln cyclonedx.Vulnerability) int {
	score := 0

	// Description adds significant value
	if vuln.Description != "" && len(strings.TrimSpace(vuln.Description)) > 10 {
		score += 15
	}

	// Ratings are crucial for vulnerability assessment
	if vuln.Ratings != nil && len(*vuln.Ratings) > 0 {
		score += 20
		// Additional points for CVSS scores
		for _, rating := range *vuln.Ratings {
			if rating.Score != nil && *rating.Score > 0 {
				score += 10
			}
		}
	}

	// Affects information is important for impact assessment
	if vuln.Affects != nil && len(*vuln.Affects) > 0 {
		score += 10
		// More points for detailed affects
		for _, affect := range *vuln.Affects {
			if affect.Ref != "" {
				score += 5
			}
		}
	}

	// Recommendation adds remediation value
	if vuln.Recommendation != "" && len(strings.TrimSpace(vuln.Recommendation)) > 10 {
		score += 8
	}

	// Analysis adds context
	if vuln.Analysis != nil {
		score += 5
	}

	// Properties add metadata value
	if vuln.Properties != nil && len(*vuln.Properties) > 0 {
		score += 3
	}

	// References add additional context
	if vuln.References != nil && len(*vuln.References) > 0 {
		score += 2
	}

	return score
}
