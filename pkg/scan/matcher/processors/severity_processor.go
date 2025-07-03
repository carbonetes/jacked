package processors

import (
	"fmt"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// SeverityThresholdProcessor handles severity-based filtering and failure logic
type SeverityThresholdProcessor struct {
	threshold matchertypes.Severity
	enabled   bool
}

// SeverityThresholdError represents an error when severity threshold is exceeded
type SeverityThresholdError struct {
	Threshold matchertypes.Severity
	Found     []SeverityCount
}

// SeverityCount represents count of vulnerabilities by severity
type SeverityCount struct {
	Severity matchertypes.Severity `json:"severity"`
	Count    int                   `json:"count"`
}

// Error implements the error interface
func (e SeverityThresholdError) Error() string {
	return fmt.Sprintf("vulnerability severity threshold exceeded: threshold=%s", string(e.Threshold))
}

// NewSeverityThresholdProcessor creates a new severity threshold processor
func NewSeverityThresholdProcessor(threshold matchertypes.Severity) *SeverityThresholdProcessor {
	return &SeverityThresholdProcessor{
		threshold: threshold,
		enabled:   threshold != "",
	}
}

// CheckSeverityThreshold checks if matches exceed the severity threshold
func (p *SeverityThresholdProcessor) CheckSeverityThreshold(matches []matchertypes.Match) error {
	if !p.enabled {
		return nil
	}

	severityCounts := p.calculateSeverityCounts(matches)

	if p.hasSeverityAtOrAbove(severityCounts) {
		return SeverityThresholdError{
			Threshold: p.threshold,
			Found:     severityCounts,
		}
	}

	return nil
}

// calculateSeverityCounts calculates vulnerability counts by severity
func (p *SeverityThresholdProcessor) calculateSeverityCounts(matches []matchertypes.Match) []SeverityCount {
	counts := make(map[matchertypes.Severity]int)

	for _, match := range matches {
		severity := p.extractSeverity(match)
		counts[severity]++
	}

	var result []SeverityCount
	for severity, count := range counts {
		result = append(result, SeverityCount{
			Severity: severity,
			Count:    count,
		})
	}

	return result
}

// hasSeverityAtOrAbove checks if any vulnerabilities meet or exceed the threshold
func (p *SeverityThresholdProcessor) hasSeverityAtOrAbove(counts []SeverityCount) bool {
	thresholdValue := p.getSeverityValue(p.threshold)

	for _, count := range counts {
		if count.Count > 0 && p.getSeverityValue(count.Severity) >= thresholdValue {
			return true
		}
	}

	return false
}

// extractSeverity extracts severity from a vulnerability match
func (p *SeverityThresholdProcessor) extractSeverity(match matchertypes.Match) matchertypes.Severity {
	// Try to extract severity from vulnerability metadata
	if match.Vulnerability.Metadata != nil {
		if severity, ok := match.Vulnerability.Metadata["severity"].(string); ok {
			return matchertypes.Severity(severity)
		}

		// Try CVSS-based severity calculation
		if cvssScore, ok := match.Vulnerability.Metadata["cvss_score"].(float64); ok {
			return p.cvssToSeverity(cvssScore)
		}
	}

	return matchertypes.UnknownSeverity
}

// getSeverityValue returns numeric value for severity comparison
func (p *SeverityThresholdProcessor) getSeverityValue(severity matchertypes.Severity) int {
	switch severity {
	case matchertypes.CriticalSeverity:
		return 4
	case matchertypes.HighSeverity:
		return 3
	case matchertypes.MediumSeverity:
		return 2
	case matchertypes.LowSeverity:
		return 1
	case matchertypes.UnknownSeverity:
		return 0
	default:
		return 0
	}
}

// cvssToSeverity converts CVSS score to severity level
func (p *SeverityThresholdProcessor) cvssToSeverity(score float64) matchertypes.Severity {
	switch {
	case score >= 9.0:
		return matchertypes.CriticalSeverity
	case score >= 7.0:
		return matchertypes.HighSeverity
	case score >= 4.0:
		return matchertypes.MediumSeverity
	case score > 0.0:
		return matchertypes.LowSeverity
	default:
		return matchertypes.UnknownSeverity
	}
}

// FilterBySeverity filters matches based on minimum severity threshold
func (p *SeverityThresholdProcessor) FilterBySeverity(matches []matchertypes.Match, minSeverity matchertypes.Severity) []matchertypes.Match {
	if minSeverity == "" {
		return matches
	}

	minValue := p.getSeverityValue(minSeverity)
	var filtered []matchertypes.Match

	for _, match := range matches {
		severity := p.extractSeverity(match)
		if p.getSeverityValue(severity) >= minValue {
			filtered = append(filtered, match)
		}
	}

	return filtered
}

// EnhanceMatchesWithSeverity adds severity information to matches
func (p *SeverityThresholdProcessor) EnhanceMatchesWithSeverity(matches []matchertypes.Match) []matchertypes.Match {
	enhanced := make([]matchertypes.Match, len(matches))

	for i, match := range matches {
		enhanced[i] = match

		// Ensure severity is in metadata
		if enhanced[i].Vulnerability.Metadata == nil {
			enhanced[i].Vulnerability.Metadata = make(map[string]interface{})
		}

		severity := p.extractSeverity(match)
		enhanced[i].Vulnerability.Metadata["normalized_severity"] = string(severity)
		enhanced[i].Vulnerability.Metadata["severity_value"] = p.getSeverityValue(severity)
	}

	return enhanced
}

// GetSeverityDistribution returns distribution of vulnerabilities by severity
func (p *SeverityThresholdProcessor) GetSeverityDistribution(matches []matchertypes.Match) map[string]int {
	distribution := make(map[string]int)

	// Initialize all severity levels
	distribution[string(matchertypes.CriticalSeverity)] = 0
	distribution[string(matchertypes.HighSeverity)] = 0
	distribution[string(matchertypes.MediumSeverity)] = 0
	distribution[string(matchertypes.LowSeverity)] = 0
	distribution[string(matchertypes.UnknownSeverity)] = 0

	for _, match := range matches {
		severity := p.extractSeverity(match)
		distribution[string(severity)]++
	}

	return distribution
}
