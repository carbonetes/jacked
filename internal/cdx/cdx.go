package cdx

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/match"
	"github.com/carbonetes/jacked/pkg/types"
)

// Aggregate processes the matches found in BOM components and updates the BOM with vex data based on the matches.
func Aggregate(matches []*match.Matcher, bom *cyclonedx.BOM) {
	if len(matches) == 0 {
		return
	}

	bom.Vulnerabilities = new([]cyclonedx.Vulnerability)
	// Get vulnerabilities from database
	vulns := db.FindVulnerabilitiesByNamespacesAndCVEs(getNamespaces(matches))
	if vulns == nil || len(*vulns) == 0 {
		log.Error("No vulnerabilities found in database")
		return
	}

	for _, m := range matches {

		if m.Matched == nil || len(m.Matched) == 0 {
			continue
		}

		// Set metadata
		setMatchMetadata(m.Matched, vulns)

		// Add VEX
		AddVex(m.Matched, m.Component, bom)
	}
}

// getNamespaces extracts namespaces from the matches.
func getNamespaces(matches []*match.Matcher) ([]string, []string) {
	if len(matches) == 0 {
		return []string{}, []string{}
	}

	namespaces := []string{}
	cves := []string{}
	for _, m := range matches {
		if m == nil {
			continue
		}

		if m.Matched == nil || len(m.Matched) == 0 {
			continue
		}

		for _, f := range m.Matched {
			namespaces = append(namespaces, f.Match.Namespace)
			cves = append(cves, f.Match.CVE)
		}
	}

	// Remove duplicates
	namespaces = helper.Unique(namespaces)

	return namespaces, cves
}

// setMatchMetadata updates the found matches with vulnerability metadata from database.
func setMatchMetadata(foundMatches []match.Found, vulns *[]types.Vulnerability) {
	if len(foundMatches) == 0 {
		return
	}

	if vulns == nil || len(*vulns) == 0 {
		return
	}

	for i, f := range foundMatches {
		for _, v := range *vulns {
			if f.Match.Namespace == v.Namespace {
				(foundMatches)[i].Metadata = v
				break
			}
		}
	}
}
