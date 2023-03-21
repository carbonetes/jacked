package analysis

import (
	"strings"
	"sync"

	"github.com/carbonetes/jacked/internal/model"
)

var WG sync.WaitGroup

func FindMatch(pkg *model.Package, vulnerabilities *[]model.Vulnerability, results *[]model.Result) {

	// check vulnerabilities if empty
	if vulnerabilities == nil {
		WG.Done()
		return
	}

	// get all vulnerabilities related to this package
	fv := filter(vulnerabilities, *pkg)

	// check filtered vulnerabilities if empty
	if len(fv) == 0 {
		WG.Done()
		return
	}

	if len(pkg.CPEs) > 0 && len(fv) > 0 {
		for _, vulnerability := range fv {
			if len(vulnerability.Criteria.CPES) > 0 && len(pkg.CPEs) > 0 {
				matched, cpe := MatchCPE(pkg, &vulnerability.Criteria)
				if matched {
					result := FormResult(vulnerability, *pkg, "= "+cpe.Version, vulnerability.Criteria)
					if !contains(results, &result) {
						*results = append(*results, result)
					}
				}
			}
			if CheckProductVendor(pkg, &vulnerability.Criteria, vulnerability.Package) && len(vulnerability.Criteria.Constraint) > 0 {
				matched, constraint := MatchConstraint(pkg.Version, vulnerability.Criteria)
				if matched {
					result := FormResult(vulnerability, *pkg, constraint, vulnerability.Criteria)
					if !contains(results, &result) {
						*results = append(*results, result)
					}
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

func FormResult(vulnerability model.Vulnerability, pkg model.Package, versionRange string, criteria model.Criteria) model.Result {

	if strings.EqualFold(vulnerability.CVSS.Severity, "UNKNOWN") {
		if strings.EqualFold(vulnerability.CVSS.Method, "2") {
			vulnerability.CVSS.Severity = GetCVSS2Severity(vulnerability.CVSS.Score)
		}
	}

	if len(vulnerability.CVSS.Method) == 0 {
		vulnerability.CVSS.Severity = "UNKNOWN"
	}

	if len(vulnerability.Remediation.Fix) == 0 {
		vulnerability.Remediation.Fix = "-"
	}

	return model.Result{
		CVE:            vulnerability.CVE,
		Package:        pkg.Name,
		CurrentVersion: pkg.Version,
		VersionRange:   versionRange,
		CVSS:           vulnerability.CVSS,
		Description:    vulnerability.Description.Content,
		Remediation:    vulnerability.Remediation,
		Reference:      vulnerability.Reference,
	}
}

func GetCVSS2Severity(baseScore float64) string {
	if baseScore >= 0.0 && baseScore <= 3.9 {
		return "LOW"
	}
	if baseScore >= 4.0 && baseScore <= 6.9 {
		return "MEDIUM"
	}
	if baseScore >= 7.0 && baseScore <= 10.0 {
		return "HIGH"
	}
	return "UNKNOWN"
}

func contains(result *[]model.Result, newResult *model.Result) bool {
	for _, r := range *result {
		if r.CVE == newResult.CVE && r.Package == newResult.Package {
			return true
		}
	}
	return false
}
