package matcher

import (
	"strings"
	"sync"

	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/model"
)

var (
	WG  sync.WaitGroup
	log = logger.GetLogger()
)

func Matcher(_package *model.Package, result *[]model.Result, vulnerabilities *[]model.Vulnerability) {

	// check vulnerabilities if empty
	if vulnerabilities == nil {
		WG.Done()
		return
	}

	// get all vulnerabilities related to this package
	fv := filter(vulnerabilities, *_package)

	// check filtered vulnerabilities if empty
	if len(fv) == 0 {
		WG.Done()
		return
	}

	for _, v := range fv {
		// Check if package cpes and vulnerability cpes are considered as matched
		cpeMatched, err := MatchCpe(_package.CPEs, v.Cpe)
		if err != nil {
			log.Errorln(err.Error())
		}

		/* If the correct vendor is not present in cpes, it will check vendor value if exist
		 * then check if package name or any keyword is matched
		 */
		criteriaMatched := matchCriteria(_package, &v)

		if cpeMatched || criteriaMatched {
			versionMatched, err := MatchVersion(_package.Version, &v)
			if err != nil {
				continue
			}
			if versionMatched {
				res := formResult(*_package, v)
				if !contains(result, &res) {
					*result = append(*result, res)
				}
			}
		}
	}

	defer WG.Done()
}

// Select all vulnerabilities can be asociated based on the keywords and vendor of the package
func filter(vulnerabilities *[]model.Vulnerability, _package model.Package) []model.Vulnerability {
	var fv []model.Vulnerability
	for _, v := range *vulnerabilities {
		if len(_package.Vendor) > 0 {
			if !strings.EqualFold(_package.Vendor, v.Vendor) {
				continue
			}
		}
		for _, keyword := range _package.Keywords {
			if len(v.Package) > 0 {
				if strings.EqualFold(v.Package, keyword) {
					fv = append(fv, v)
				}
			}
		}
	}
	return fv
}

// Construct a result for each matched vulnerability
func formResult(p model.Package, v model.Vulnerability) model.Result {
	var result model.Result
	result.CVE = v.Id
	result.CurrentVersion = p.Version
	result.Package = p.Name
	result.VersionRange = strings.Join(formatAffectedVersions(&v), ", ")
	if v.Cvssv3BaseScore > 0 {
		result.CVSS.Version = "3"
		result.CVSS.BaseScore = v.Cvssv3BaseScore
		result.CVSS.Severity = v.Cvssv3BaseSeverity
	} else {
		if v.Cvssv2BaseScore > 0 {
			result.CVSS.Version = "2"
			result.CVSS.BaseScore = v.Cvssv2BaseScore
			result.CVSS.Severity = v.Cvssv2BaseSeverity
		} else {
			result.CVSS.Severity = "Unknown"
		}
	}

	return result
}

// Create affected version ranges
func formatAffectedVersions(v *model.Vulnerability) []string {
	var affectedVersions []string
	if len(v.VersionEquals) != 0 {
		for _, version := range v.VersionEquals {
			affectedVersions = append(affectedVersions, "="+version)
		}

	}
	if len(v.VersionStartIncluding) != 0 {
		for _, version := range v.VersionStartIncluding {
			affectedVersions = append(affectedVersions, "=>"+version)
		}

	}
	if len(v.VersionStartExcluding) != 0 {
		for _, version := range v.VersionStartExcluding {
			affectedVersions = append(affectedVersions, ">"+version)
		}

	}
	if len(v.VersionEndIncluding) != 0 {
		for _, version := range v.VersionEndIncluding {
			affectedVersions = append(affectedVersions, "<="+version)
		}

	}
	if len(v.VersionEndExcluding) != 0 {
		for _, version := range v.VersionEndExcluding {
			affectedVersions = append(affectedVersions, "<"+version)
		}

	}
	return affectedVersions
}

// Check if cve is already exists in the collection of scan results of the given package
func contains(result *[]model.Result, newResult *model.Result) bool {
	for _, r := range *result {
		if r.CVE == newResult.CVE && r.Package == newResult.Package {
			return true
		}
	}
	return false
}
