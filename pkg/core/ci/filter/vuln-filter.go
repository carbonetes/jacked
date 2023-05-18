package filter

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/config"
	"golang.org/x/exp/slices"
)

var (
	indexes               []int
	enabledfilterSeverity bool
	enabledfilterCVE      bool
)

// Check and locate and remove all of elements that matches the values based ignore policy in configuration
func IgnoreVuln(vulnerabilities *[]cyclonedx.Vulnerability, ignore *config.Vulnerability) {

	// Check ignore filter
	enabledfilterCVE = len(ignore.CVE) > 0
	enabledfilterSeverity = len(ignore.Severity) > 0
	if enabledfilterCVE || enabledfilterSeverity {
		filterIndex(vulnerabilities, ignore)
	}

	if len(indexes) > 0 {
		for i := len(indexes) - 1; i >= 0; i-- {

			indexToRemove := indexes[i]

			// Slice if array element exist
			if len(*vulnerabilities) > indexToRemove {
				*vulnerabilities = append((*vulnerabilities)[:indexToRemove], (*vulnerabilities)[indexToRemove+1:]...)
			}
		}
	}
}

func filterIndex(vulnerabilities *[]cyclonedx.Vulnerability, ignore *config.Vulnerability) {
	for index, vulnerability := range *vulnerabilities {
		// CVE Filter
		if enabledfilterCVE {
			id := vulnerability.ID
			cves := ignore.CVE
			filterCVE(id, cves, index)
		}

		// Severities Filter
		if enabledfilterSeverity {
			filterSeverity(getSeverity(vulnerability.Ratings), ignore, &vulnerability, index)
		}
	}
}

func filterCVE(id string, cves []string, index int) {
	for _, cve := range cves {
		if strings.EqualFold(id, cve) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}
}

// Filter all severities listed in vulnerability ignore list
func filterSeverity(vulnSeverity string, ignore *config.Vulnerability, vulnerability *cyclonedx.Vulnerability, index int) {

	for _, severity := range ignore.Severity {
		if strings.EqualFold(vulnSeverity, severity) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}

}


func getSeverity(ratings *[]cyclonedx.VulnerabilityRating) string {
	if len(*ratings) == 0 {
		return "UNKNOWN"
	}

	for _, rating := range *ratings {
		if len(rating.Severity) > 0 {
			return string(rating.Severity)
		}
	}
	return "UNKNOWN"
}
