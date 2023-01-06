package db

import (
	"strings"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"golang.org/x/exp/slices"
)

var indexes []int

// Check and locate and remove all of elements that matches the values based ignore policy in configuration
func Filter(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {
	if len(ignore.CVE) > 0 {
		filterCVE(vulnerabilities, ignore)
	}
	if len(ignore.Severity) > 0 {
		filterSeverity(vulnerabilities, ignore)
	}
	// Remove elements with index found in filter
	if len(indexes) > 0 {
		for i := len(indexes) - 1; i >= 0; i-- {
			indexToRemove := indexes[i]
			*vulnerabilities = append((*vulnerabilities)[:indexToRemove], (*vulnerabilities)[indexToRemove+1:]...)
		}
	}
}

// Filter all CVEs listed in vulnerability ignore list
func filterCVE(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {
	for index, vulnerability := range *vulnerabilities {
		for _, cve := range ignore.CVE {
			if strings.EqualFold(vulnerability.Id, cve) {
				if !slices.Contains(indexes, index) {
					indexes = append(indexes, index)
				}
			}
		}
	}
}

// Filter all severities listed in vulnerability ignore list
func filterSeverity(vulnerabilities *[]model.Vulnerability, ignore *config.Vulnerability) {
	for index, vulnerability := range *vulnerabilities {
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
}
