package ci

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/types"
)

// TODO: Implement more CI logic
func Run(ci types.CIConfiguration, cdx *cyclonedx.BOM) {
	totalComponents := len(*cdx.Components)

	if cdx.Vulnerabilities == nil {
		log.Infof("\nPassed: No Vulnerabilities Found.")
		return
	}

	totalVulns := len(*cdx.Vulnerabilities)
	log.Printf("\nPackages: %9v\nVulnerabilities: %v", totalComponents, totalVulns)

	if totalVulns == 0 {
		log.Printf("\nPassed: %5v found components\n", totalComponents)
		return
	}

	result := Evaluate(ci.FailCriteria.Severity, cdx)
	log.Printf("\nTally Result")
	TallyTable(result.Tally)
	log.Print("\nMatch Table Result\n")
	MatchTable(result.Matches)

	for _, m := range result.Matches {
		if len(m.Vulnerability.Recommendation) > 0 {
			log.Warnf("[%v] : %v", m.Vulnerability.ID, m.Vulnerability.Recommendation)
		}
	}

	if !result.Passed {
		log.Fatalf("\nFailed: %5v out of %v found vulnerabilities failed the assessment \n", len(result.Matches), totalVulns)
	} else {
		log.Infof("\nPassed: %5v out of %v found vulnerabilities passed the assessment\n", totalVulns, totalVulns)
	}
}
