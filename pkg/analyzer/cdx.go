package analyzer

import (
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/tea/spinner"
	"github.com/carbonetes/jacked/pkg/types"
)

// diggity cpe2.3 property flag
const cpe = "cpe23"

var (
	// Create an empty slice for storing the found vulnerabilities.
	vexList *[]cyclonedx.Vulnerability
	lock    sync.RWMutex
)

func init() {
	vexList = new([]cyclonedx.Vulnerability)
}

// AnalyzeCDX is a function that accepts a CycloneDX BOM (Software Bill of Materials) as input.
// It calls findMatchingVulnerabilities to search for vulnerabilities affecting the components in the BOM, and appends any found vulnerabilities to the BOM's Vulnerabilities list.
func AnalyzeCDX(sbom *cyclonedx.BOM) {
	// If there are no components in the BOM, return immediately.
	if len(*sbom.Components) == 0 {
		return
	}
	// Call findMatchingVulnerabilities to get a list of matching vulnerabilities for the BOM.
	findMatchingVulnerabilities(sbom)
	// Create a new empty slice for storing the vulnerabilities found.
	sbom.Vulnerabilities = new([]cyclonedx.Vulnerability)
	// Append the vulnerabilities in vexList to the BOM's Vulnerabilities slice.
	*sbom.Vulnerabilities = append(*sbom.Vulnerabilities, *vexList...)
}

// findMatchingVulnerabilities is a helper function called by AnalyzeCDX.
// It searches for vulnerabilities affecting the components in the BOM, and adds any found vulnerabilities to the BOM's Vulnerabilities list.
func findMatchingVulnerabilities(sbom *cyclonedx.BOM) {
	// Create a WaitGroup to wait until all component analysis goroutines have completed.
	var wg sync.WaitGroup
	// Use findVulnerabilitiesForPackages to look up known vulnerabilities for the components in the BOM.
	// Return early if there are no known vulnerabilities.
	vulnerabilities := findVulnerabilitiesForPackages(sbom.Components)
	if vulnerabilities == nil {
		return
	}

	spinner.Status("Analyzing components for vulnerabilities")
	// Loop through each component in the BOM.
	// Spawn a goroutine to analyze each component for matching vulnerabilities.
	wg.Add(len(*sbom.Components))
	for _, c := range *sbom.Components {
		go func(comp cyclonedx.Component) {
			// Decrement the WaitGroup counter when analysis is complete.
			defer wg.Done()
			spinner.Status("Analyzing " + comp.Name)
			// Look up known vulnerabilities for the current component.
			packageVulnerabilties := filterVulnerabilitiesByKeyword(&comp.Name, vulnerabilities)

			// Extract the CPEs (Common Platform Enumeration) associated with the component, if any.
			cpes := getCPES(comp.Properties)
			if len(comp.CPE) != 0 {
				cpes = append(cpes, comp.CPE)
			}
			// Loop through each known vulnerability and check if it applies to the current component.
			// If a match is found, create a new Vulnerability Exploitability eXchange (VEX) record for the component/vulnerability pair and add it to vexList.
			for _, v := range *packageVulnerabilties {
				if MatchConstraint(&comp.Version, &v.Criteria) ||
					len(cpes) > 0 && MatchCPE(cpes, &v.Criteria) {
					vex := ToVex(&comp, &v)
					// vexList = append(vexList, *vex)
					AddVex(vex)
				}
			}
		}(c)
	}
	// Wait for all component analysis goroutines to complete before returning vexList.
	wg.Wait()
}

// getCPES is a helper function used by findMatchingVulnerabilities.
// It extracts an array of CPE strings associated with the component properties, if any.
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

// findVulnerabilitiesForPackages is a helper function used by findMatchingVulnerabilities.
// It looks up known vulnerabilities for the components in pkgs and returns them as a slice of types.Vulnerability structs.
func findVulnerabilitiesForPackages(pkgs *[]cyclonedx.Component) *[]types.Vulnerability {
	// Create a new empty slice for storing the found vulnerabilities.
	vulnerabilities := new([]types.Vulnerability)
	// Create a new empty slice for storing search keywords (i.e. package names).
	keywords := new([]string)
	// Loop through each component in the BOM and add its name to the keywords list.
	for _, pkg := range *pkgs {
		if len(pkg.Name) > 0 {
			*keywords = append(*keywords, pkg.Name)
		}
	}
	// Call db.FindPackage to find vulnerabilities matching any of the keywords.
	db.FindByKeywords(keywords, vulnerabilities)
	// Return nil if no vulnerabilities were found, otherwise return the found vulnerabilities.
	return vulnerabilities
}

func filterVulnerabilitiesByKeyword(keyword *string, vulnerabilities *[]types.Vulnerability) *[]types.Vulnerability {
	filtered := new([]types.Vulnerability)
	for _, v := range *vulnerabilities {
		if v.Package == *keyword {
			*filtered = append(*filtered, v)
		}
	}
	return filtered
}

func AddVex(vex *cyclonedx.Vulnerability) {
	lock.Lock()
	defer lock.Unlock()

	if vex == nil {
		return
	}

	// check if the vulnerability already exists in the list
	for _, v := range *vexList {
		if v.ID == vex.ID && v.BOMRef == vex.BOMRef {
			return
		}
	}

	*vexList = append(*vexList, *vex)
}
