package analysis

import (
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/analysis"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/model"
)

// diggity cpe2.3 property flag
const cpe = "diggity:cpe23"

// AnalyzeCDX analyzes the given sbom to find vulnerabilities.
// It takes a pointer to cyclonedx.BOM, which contains information about components.
func AnalyzeCDX(sbom *cyclonedx.BOM) {

	// Check if there are any components in the sbom. If not, return.
	if len(*sbom.Components) == 0 {
		return
	}

	// Find vulnerabilities that match the components in the sbom.
	vexList := findMatchingVulnerabilities(sbom)

	// Create a new list of vulnerabilities in the sbom and append the found vulnerabilities to it.
	sbom.Vulnerabilities = new([]cyclonedx.Vulnerability)
	*sbom.Vulnerabilities = append(*sbom.Vulnerabilities, *vexList...)
}

// findMatchingVulnerabilities returns a pointer to a slice of vulnerabilities that match the criteria for a given BOM.
// The function takes a pointer to a CycloneDX BOM structure as input and creates a new slice of vulnerabilities.
// It then iterates through all components in the BOM in parallel using goroutines, finds any vulnerabilities related to
// that component, checks if it matches the criteria, and appends them to the vexList slice. Finally, it waits for all
// goroutines to finish and returns a pointer to the populated vexList slice.
func findMatchingVulnerabilities(sbom *cyclonedx.BOM) *[]cyclonedx.Vulnerability {
	vexList := []cyclonedx.Vulnerability{}
	var wg sync.WaitGroup
	wg.Add(len(*sbom.Components))
	for _, c := range *sbom.Components {
		go func(comp cyclonedx.Component) {
			defer wg.Done()
			vulnerabilities := findVulnerabilitiesForPackage(&comp)
			cpes := getCPES(comp.Properties)
			// iterates through all vulnerabilities for the component checking if they meet either of the following criteria:
			// 1. match component version constraints or
			// 2. match CPEs associated with the component properties
			for _, v := range *vulnerabilities {
				if analysis.MatchConstraint(&comp.Version, &v.Criteria) ||
					len(cpes) > 0 && MatchCPE(cpes, &v.Criteria) {
					// create a new VEX structure for the matched vulnerability and append it to vexList
					vex := NewVEX(&comp, &v)
					vexList = append(vexList, *vex)
				}
			}
		}(c)
	}
	// wait for all goroutines to complete before returning vexList
	wg.Wait()
	return &vexList
}

// getCPES returns a slice of strings representing Common Platform Enumeration (CPE) names that are associated with a component.
// The function takes a pointer to a slice of CycloneDX properties as input, which detail the properties of the component.
// It first initializes an empty slice for cpes, and then iterates through each property in the slice. If the name of the
// current property is equal to the string "cpe", it will append the value of that property to the cpes slice.
// After iterating through all properties, the function returns the cpes slice.
func getCPES(c *[]cyclonedx.Property) []string {
	var cpes []string
	if c != nil {
		for _, p := range *c {
			if p.Name == cpe {
				cpes = append(cpes, p.Value)
			}
		}
	}
	return cpes
}

// findVulnerabilitiesForPackage function takes a pointer to a CycloneDX component as input, and uses its name property
// to search our database for any associated vulnerabilities with that package. The function returns a pointer to a slice of
// model.Vulnerability objects found in the database.
func findVulnerabilitiesForPackage(pkg *cyclonedx.Component) *[]model.Vulnerability {
	// Initialize an empty pointer to a slice of Vulnerability objects.
	vulnerabilities := new([]model.Vulnerability)

	// Search database for vulnerabilities related to current package
	db.FindPackage(pkg.Name, vulnerabilities)

	// Return pointer to slice of vulnerabilities found
	return vulnerabilities
}

// NewVEX function creates a new CycloneDX vulnerability object given a pointer to a CycloneDX component and
// a pointer to a model.Vulnerability object. The function initializes the new vulnerability object with data such as
// vulnerability rating, source of the vulnerability, description and recommendation to fix the vulnerability.
func NewVEX(pkg *cyclonedx.Component, vuln *model.Vulnerability) *cyclonedx.Vulnerability {
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
