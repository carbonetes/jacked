package analyzer

import (
	"strconv"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/helper"
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
	var rating cyclonedx.VulnerabilityRating
	if len(vuln.CVSS.Method) > 0 {
		rating.Method = cyclonedx.ScoringMethod(vuln.CVSS.Method)
		rating.Score = &vuln.CVSS.Score
		rating.Severity = cyclonedx.Severity(vuln.CVSS.Severity)
		rating.Vector = vuln.CVSS.Vector
		*ratings = append(*ratings, rating)
	} else {
		rating.Severity = cyclonedx.Severity("unknown")
	}

	// Create a recommendation string to suggest how to solve the vulnerability (if possible)
	var recommendation string
	if len(vuln.Remediation.Fix) > 0 {
		recommendation += "Upgrade " + pkg.Name + " to " + vuln.Remediation.Fix
	}

	// Initialize a new pointer to slice of Affects objects, which will hold all affected versions for given vulnerability.
	affects := new([]cyclonedx.Affects)
	affect := new(cyclonedx.Affects)
	affect.Ref = pkg.PackageURL + "?id=" + pkg.BOMRef
	ranges := new([]cyclonedx.AffectedVersions)
	// If there are any CPEs or constraints in the vulnerability criteria, add them to the affected versions.
	if len(vuln.Criteria.CPES) > 0 {
		for _, cpe := range vuln.Criteria.CPES {
			affected := new(cyclonedx.AffectedVersions)
			affected.Version = cpe
			parts := helper.SplitCpe(cpe)
			if len(parts) > 6 {
				if parts[5] != "*" {
					affected.Status = cyclonedx.VulnerabilityStatusAffected
				} else {
					affected.Status = cyclonedx.VulnerabilityStatusUnknown
				}
			}
			*ranges = append(*ranges, *affected)
		}
	}

	// If there are any constraints in the vulnerability criteria, add them to the affected versions as well.
	if len(vuln.Criteria.Constraint) > 0 {
		affected := new(cyclonedx.AffectedVersions)
		affected.Range = vuln.Criteria.Constraint
		affected.Status = cyclonedx.VulnerabilityStatusAffected
		*ranges = append(*ranges, *affected)
	}

	// Add the affected versions to the Affects object.
	affect.Range = new([]cyclonedx.AffectedVersions)
	*affect.Range = append(*affect.Range, *ranges...)
	*affects = append(*affects, *affect)

	// Jacked-DB Entry Ref: This is where the vulnerability data is pulled from the Jacked-DB.
	entryRef := new(cyclonedx.Affects)
	entryRef.Ref = "jacked-db:" + strconv.FormatInt(vuln.ID, 10)
	*affects = append(*affects, *entryRef)

	// Return a new CycloneDX Vulnerability object initialized with the above data.
	return &cyclonedx.Vulnerability{
		BOMRef:         pkg.BOMRef,
		ID:             vuln.CVE,
		Source:         source,
		Ratings:        ratings,
		Description:    vuln.Description.Content,
		Recommendation: recommendation,
		Affects:        affects,
	}
}
