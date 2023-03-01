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
		filter(vulnerabilities, ignore)
	}

	// Remove elements with index found in filter
	if len(indexes) > 0 {
		for i := len(indexes) - 1; i >= 0; i-- {

			indexToRemove := indexes[i]

			// Slice if array element exist
			if len(*vulnerabilities) > indexToRemove {
				*vulnerabilities = append((*vulnerabilities)[:indexToRemove], (*vulnerabilities)[indexToRemove+1:]...)
			} else {

				log.Printf("testing: %v = %v", len(*vulnerabilities) > indexToRemove, indexToRemove)
			}
		}
	}
}

// Filter all CVEs and Severities on ignore list
func filter(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {

	for index, vulnerability := range *vulnerabilities {

		// CVEs Filter
		if enabledfilterCVE {
			id := vulnerability.Id
			cves := ignore.CVE
			filterCVE(id, cves, index)
		}

		// Severities Filter
		if enabledfilterSeverity {
			filterSeverity(vulnerability, ignore, index)
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
func filterSeverity(vulnerability model.Vulnerability, ignore *config.Vulnerability, index int) {

	for _, severity := range ignore.Severity {
		if vulnerability.Cvssv3BaseScore > 0 && strings.EqualFold(vulnerability.Cvssv3BaseSeverity, severity) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		} else if vulnerability.Cvssv2BaseScore > 0 && strings.EqualFold(vulnerability.Cvssv2BaseSeverity, severity) {
			if !slices.Contains(indexes, index) {
				indexes = append(indexes, index)
			}
		} else {
			if strings.EqualFold(severity, "Unknown") && len(vulnerability.Cvssv2BaseSeverity) == 0 && len(vulnerability.Cvssv3BaseSeverity) == 0 {
				if !slices.Contains(indexes, index) {
					indexes = append(indexes, index)
				}
			}
		}
	}
}
