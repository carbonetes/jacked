package analyzer

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/cdx"
	"github.com/carbonetes/jacked/internal/match"
)

// AnalyzerCDX performs vulnerability analysis on a CycloneDX BOM.
// It finds matches for components in the BOM and aggregates them using internal cdx package functionalities.
func AnalyzeCDX(bom *cyclonedx.BOM) {
	if bom == nil || len(*bom.Components) == 0 {
		return
	}

	matches := match.Find(*bom)
	cdx.Aggregate(matches, bom)
}
