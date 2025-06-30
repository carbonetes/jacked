package processors

import (
	"slices"
	"strings"

	"github.com/carbonetes/jacked/pkg/scan/matchertypes"
)

// CVENormalizer consolidates related vulnerabilities by CVE ID similar to Grype's approach
type CVENormalizer struct {
	enabled bool
}

// NewCVENormalizer creates a new CVE normalizer
func NewCVENormalizer(enabled bool) *CVENormalizer {
	return &CVENormalizer{
		enabled: enabled,
	}
}

// NormalizeMatches consolidates matches by CVE ID, preferring CVE entries over other sources
func (n *CVENormalizer) NormalizeMatches(matches []matchertypes.Match) []matchertypes.Match {
	if !n.enabled {
		return matches
	}

	// Group matches by CVE ID
	cveGroups := n.groupMatchesByCVE(matches)

	var normalizedMatches []matchertypes.Match
	processedCVEs := make(map[string]bool)

	for _, match := range matches {
		cveID := n.extractCVEID(match)

		if cveID == "" {
			// No CVE ID, keep the match as-is
			normalizedMatches = append(normalizedMatches, match)
			continue
		}

		if processedCVEs[cveID] {
			// Already processed this CVE, skip
			continue
		}

		// Get all matches for this CVE and normalize them
		cveMatches := cveGroups[cveID]
		normalizedMatch := n.createNormalizedMatch(cveMatches, cveID)
		normalizedMatches = append(normalizedMatches, normalizedMatch)
		processedCVEs[cveID] = true
	}

	return normalizedMatches
}

// groupMatchesByCVE groups matches by their CVE IDs
func (n *CVENormalizer) groupMatchesByCVE(matches []matchertypes.Match) map[string][]matchertypes.Match {
	groups := make(map[string][]matchertypes.Match)

	for _, match := range matches {
		cveID := n.extractCVEID(match)
		if cveID != "" {
			groups[cveID] = append(groups[cveID], match)
		}
	}

	return groups
}

// extractCVEID extracts the CVE ID from a vulnerability match
func (n *CVENormalizer) extractCVEID(match matchertypes.Match) string {
	// Check if the vulnerability ID is already a CVE
	if n.isCVEID(match.Vulnerability.ID) {
		return match.Vulnerability.ID
	}

	// Check related vulnerabilities for CVE IDs
	for _, related := range match.Vulnerability.RelatedVulnerabilities {
		if n.isCVEID(related.ID) {
			return related.ID
		}
	}

	// Check metadata for CVE references
	if match.Vulnerability.Metadata != nil {
		if cveID, ok := match.Vulnerability.Metadata["cve_id"].(string); ok && n.isCVEID(cveID) {
			return cveID
		}
	}

	return ""
}

// isCVEID checks if an ID follows CVE format
func (n *CVENormalizer) isCVEID(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

// createNormalizedMatch creates a consolidated match from multiple CVE-related matches
func (n *CVENormalizer) createNormalizedMatch(matches []matchertypes.Match, cveID string) matchertypes.Match {
	if len(matches) == 0 {
		return matchertypes.Match{}
	}

	// Prefer CVE entries over other sources (like GHSA)
	primaryMatch := n.selectPrimaryMatch(matches, cveID)

	// Consolidate information from all matches
	consolidatedMatch := primaryMatch
	consolidatedMatch.Vulnerability.ID = cveID
	consolidatedMatch.Vulnerability.Namespace = n.selectBestNamespace(matches)

	// Consolidate related vulnerabilities
	consolidatedMatch.Vulnerability.RelatedVulnerabilities = n.consolidateRelatedVulnerabilities(matches, cveID)

	// Consolidate advisories
	consolidatedMatch.Vulnerability.Advisories = n.consolidateAdvisories(matches)

	// Consolidate match details
	consolidatedMatch.Details = n.consolidateMatchDetails(matches)

	// Enhance metadata
	consolidatedMatch.Vulnerability.Metadata = n.consolidateMetadata(matches)

	return consolidatedMatch
}

// selectPrimaryMatch selects the best match to use as the primary source
func (n *CVENormalizer) selectPrimaryMatch(matches []matchertypes.Match, cveID string) matchertypes.Match {
	// Preference order: 1) CVE namespace, 2) NVD, 3) others
	priorities := []string{"nvd:cpe", "nvd", "cve"}

	for _, priority := range priorities {
		for _, match := range matches {
			if strings.Contains(strings.ToLower(match.Vulnerability.Namespace), priority) {
				return match
			}
		}
	}

	// If no preferred namespace found, prefer direct CVE ID matches
	for _, match := range matches {
		if match.Vulnerability.ID == cveID {
			return match
		}
	}

	// Fallback to first match
	return matches[0]
}

// selectBestNamespace selects the most authoritative namespace
func (n *CVENormalizer) selectBestNamespace(matches []matchertypes.Match) string {
	namespaces := make([]string, 0, len(matches))
	for _, match := range matches {
		namespaces = append(namespaces, match.Vulnerability.Namespace)
	}

	// Prefer NVD namespaces
	for _, namespace := range namespaces {
		if strings.Contains(strings.ToLower(namespace), "nvd") {
			return namespace
		}
	}

	// Prefer CVE namespaces
	for _, namespace := range namespaces {
		if strings.Contains(strings.ToLower(namespace), "cve") {
			return namespace
		}
	}

	// Return first available
	if len(namespaces) > 0 {
		return namespaces[0]
	}

	return ""
}

// consolidateRelatedVulnerabilities combines related vulnerabilities from all matches
func (n *CVENormalizer) consolidateRelatedVulnerabilities(matches []matchertypes.Match, primaryCVE string) []matchertypes.VulnerabilityRef {
	seen := make(map[string]bool)
	var consolidated []matchertypes.VulnerabilityRef

	for _, match := range matches {
		// Add the original vulnerability ID as a related vulnerability if it's not the primary CVE
		if match.Vulnerability.ID != primaryCVE && !seen[match.Vulnerability.ID] {
			consolidated = append(consolidated, matchertypes.VulnerabilityRef{
				ID:        match.Vulnerability.ID,
				Namespace: match.Vulnerability.Namespace,
			})
			seen[match.Vulnerability.ID] = true
		}

		// Add existing related vulnerabilities
		for _, related := range match.Vulnerability.RelatedVulnerabilities {
			if related.ID != primaryCVE && !seen[related.ID] {
				consolidated = append(consolidated, related)
				seen[related.ID] = true
			}
		}
	}

	return consolidated
}

// consolidateAdvisories combines advisories from all matches
func (n *CVENormalizer) consolidateAdvisories(matches []matchertypes.Match) []matchertypes.Advisory {
	seen := make(map[string]bool)
	var consolidated []matchertypes.Advisory

	for _, match := range matches {
		for _, advisory := range match.Vulnerability.Advisories {
			if !seen[advisory.ID] {
				consolidated = append(consolidated, advisory)
				seen[advisory.ID] = true
			}
		}
	}

	return consolidated
}

// consolidateMatchDetails combines match details from all matches
func (n *CVENormalizer) consolidateMatchDetails(matches []matchertypes.Match) []matchertypes.MatchDetail {
	var consolidated []matchertypes.MatchDetail

	for _, match := range matches {
		consolidated = append(consolidated, match.Details...)
	}

	return consolidated
}

// consolidateMetadata combines metadata from all matches
func (n *CVENormalizer) consolidateMetadata(matches []matchertypes.Match) map[string]interface{} {
	consolidated := make(map[string]interface{})

	// Collect all metadata
	for _, match := range matches {
		if match.Vulnerability.Metadata != nil {
			for key, value := range match.Vulnerability.Metadata {
				consolidated[key] = value
			}
		}
	}

	// Add normalization info
	consolidated["normalized_by_cve"] = true
	consolidated["source_count"] = len(matches)

	// Extract best severity and CVSS score
	n.consolidateSeverityInfo(matches, consolidated)

	return consolidated
}

// consolidateSeverityInfo extracts and consolidates severity information
func (n *CVENormalizer) consolidateSeverityInfo(matches []matchertypes.Match, metadata map[string]interface{}) {
	var severities []string
	var cvssScores []float64

	for _, match := range matches {
		if match.Vulnerability.Metadata != nil {
			if severity, ok := match.Vulnerability.Metadata["severity"].(string); ok {
				severities = append(severities, severity)
			}
			if score, ok := match.Vulnerability.Metadata["cvss_score"].(float64); ok {
				cvssScores = append(cvssScores, score)
			}
		}
	}

	// Use highest severity
	if len(severities) > 0 {
		metadata["severity"] = n.getHighestSeverity(severities)
	}

	// Use highest CVSS score
	if len(cvssScores) > 0 {
		slices.Sort(cvssScores)
		metadata["cvss_score"] = cvssScores[len(cvssScores)-1]
	}
}

// getHighestSeverity returns the highest severity from a list
func (n *CVENormalizer) getHighestSeverity(severities []string) string {
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"unknown":  0,
	}

	highest := ""
	highestLevel := -1

	for _, severity := range severities {
		level, exists := severityLevels[strings.ToLower(severity)]
		if exists && level > highestLevel {
			highest = severity
			highestLevel = level
		}
	}

	return highest
}
