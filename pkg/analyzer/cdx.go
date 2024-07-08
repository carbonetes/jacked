package analyzer

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/compare"
)

// AnalyzeCDX is a function that takes a CycloneDX BOM as input and analyzes it for vulnerabilities.
func AnalyzeCDX(sbom *cyclonedx.BOM) {
	// If the BOM is nil, return immediately.
	if sbom == nil {
		return
	}

	// If there are no components in the BOM, return immediately.
	if len(*sbom.Components) == 0 {
		return
	}

	// Call in the compare package to execute the comparison of the BOM.
	// The comparison will search for vulnerabilities affecting the components in the BOM and append any found vulnerabilities to the BOM's Vulnerabilities list.
	compare.Analyze(sbom)
}
