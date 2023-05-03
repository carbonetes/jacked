package analysis

import (
	"github.com/CycloneDX/cyclonedx-go"
	jacked "github.com/carbonetes/jacked/internal/analysis/cyclonedx"
)

// AnalyzeCDX is a function that takes in a CycloneDX BOM pointer and analyzes it using the `analysis` package.
// Input: a pointer to a CycloneDX BOM object (`*cyclonedx.BOM`)
// Output: possibly modified CycloneDX BOM object (`*cyclonedx.BOM`)
func AnalyzeCDX(sbom *cyclonedx.BOM) {
	// Call the `AnalyzeCDX()` function from the `analysis` package, passing in the `sbom` pointer as an argument.
	// This function analyzes the CDX BOM and will likely modify it in some way.
	jacked.AnalyzeCDX(sbom)
}