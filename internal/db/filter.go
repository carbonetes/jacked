package db

import (
	"strings"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"golang.org/x/exp/slices"
)

var (
	indexes               []int
	enabledfilterSeverity bool
	enabledfilterCVE      bool
)

// Check and locate and remove all of elements that matches the values based ignore policy in configuration
func Filter(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {

	// Check ignore filter
	enabledfilterCVE = len(ignore.CVE) > 0
	enabledfilterSeverity = len(ignore.Severity) > 0
	if enabledfilterCVE || enabledfilterSeverity {
		filterIndex(vulnerabilities, ignore)
	}

	// Remove elements with index found in filter
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

// Filter all CVEs and Severities on ignore list
func filterIndex(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {

	for index, vulnerability := range *vulnerabilities {

		// CVEs Filter
		if enabledfilterCVE {
			id := vulnerability.CVE
			cves := ignore.CVE
			filterCVE(id, cves, index)

		}

		// Severities Filter
		if enabledfilterSeverity {
			filterSeverity(vulnerability.CVSS, ignore, vulnerability, index)
		}

	}
}

// Filter all CVEs listed in vulnerability ignore list
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
func filterSeverity(cvss model.CVSS, ignore *config.Vulnerability, vulnerability model.Vulnerability, index int) {

	for _, severity := range ignore.Severity {
		if strings.EqualFold(cvss.Severity, severity) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		}
	}

}
