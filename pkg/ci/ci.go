package ci

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/config"
)

var Severities = []string{
	"unknown",
	"negligible",
	"low",
	"medium",
	"high",
	"critical",
}

func GetJoinedSeverities() string {
	return strings.Join(Severities, ", ")
}

func IsValidSeverity(severity string) bool {
	for _, s := range Severities {
		if s == severity {
			return true
		}
	}
	return false
}

// CIModeConfig holds CI-related configuration
type CIModeConfig struct {
	Quiet        bool
	FailCriteria string
}

// SetupCIMode configures CI-related settings and returns the configuration
func SetupCIMode(ci, quiet bool, failCriteria string) CIModeConfig {
	ciMode := CIModeConfig{
		Quiet:        quiet,
		FailCriteria: failCriteria,
	}

	if ci {
		ciMode.Quiet = true

		if len(failCriteria) == 0 || !IsValidSeverity(failCriteria) {
			log.Warn("CI mode is enabled, but no valid fail criteria is provided")
			log.Warn("Default fail criteria will be used: 'critical' severity vulnerabilities will fail the build")
			ciMode.FailCriteria = "critical"
		}
	} else {
		if len(failCriteria) > 0 {
			log.Warn("CI mode is not enabled, fail criteria will not be used")
		}
	}

	return ciMode
}

// Run implements CI logic for vulnerability analysis
func Run(ci config.CIConfiguration, cdx *cyclonedx.BOM) {
	var totalComponents, totalVulnerabilities int

	if cdx.Components != nil {
		totalComponents = len(*cdx.Components)
	}
	if cdx.Vulnerabilities != nil {
		totalVulnerabilities = len(*cdx.Vulnerabilities)
	}

	log.Printf("\nPackages: %9v\nVulnerabilities: %v", totalComponents, totalVulnerabilities)
	if cdx.Vulnerabilities == nil || len(*cdx.Vulnerabilities) == 0 {
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
		log.Fatalf("\nFailed: %5v out of %v found vulnerabilities failed the assessment \n", len(result.Matches), totalVulnerabilities)

	}

	log.Infof("\nPassed: %5v out of %v found vulnerabilities passed the assessment\n", totalVulnerabilities, totalVulnerabilities)
}
