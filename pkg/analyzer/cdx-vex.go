package analyzer

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
)

// ToVex function creates a new CycloneDX vulnerability object given a pointer to a CycloneDX component and
// a pointer to a types.Vulnerability object. The function initializes the new vulnerability object with data such as
// vulnerability rating, source of the vulnerability, description and recommendation to fix the vulnerability.
func ToVex(pkg *cyclonedx.Component, vuln *types.Vulnerability) *cyclonedx.Vulnerability {
	// Initialize a new Source object to store information about the vulnerability's source (if available)
	source := new(cyclonedx.Source)
	if len(vuln.Reference.Source) > 0 {
		source.Name = vuln.Reference.Source
		source.URL = vuln.Reference.URL
	}

	// Initialize a new pointer to slice of VulnerabilityRating objects, which will hold all ratings for given vulnerability.
	ratings := new([]cyclonedx.VulnerabilityRating)

	// If a scoring method is available (based on CVSS), add a new VulnerabilityRating struct using it.
	if len(vuln.CVSS.Method) > 0 {
		var rating cyclonedx.VulnerabilityRating
		rating.Method = cyclonedx.ScoringMethod(vuln.CVSS.Method)
		rating.Score = &vuln.CVSS.Score
		rating.Severity = cyclonedx.Severity(vuln.CVSS.Severity)
		rating.Vector = vuln.CVSS.Vector
		*ratings = append(*ratings, rating)
	}

	// Create a recommendation string to suggest how to solve the vulnerability (if possible)
	var recommendation string
	if len(vuln.Remediation.Fix) > 0 {
		recommendation += "Upgrade " + pkg.Name + " to " + vuln.Remediation.Fix
	}

	// Return a new CycloneDX Vulnerability object initialized with the above data.
	return &cyclonedx.Vulnerability{
		BOMRef:         pkg.BOMRef,
		ID:             vuln.CVE,
		Source:         source,
		Ratings:        ratings,
		Description:    vuln.Description.Content,
		Recommendation: recommendation,
	}
}
