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
	fv := filter(vulnerabilities, &pkg.Keywords)

	// check filtered vulnerabilities if empty
	if len(fv) == 0 {
		WG.Done()
		return
	}

	if len(pkg.CPEs) > 0 && len(fv) > 0 {
		for _, vulnerability := range fv {
			matched := match(pkg, &vulnerability)
			if matched {
				result := FormResult(&vulnerability, pkg)
				if !contains(results, &result) {
					*results = append(*results, result)
				}
			}

		}
	}

	defer WG.Done()
}

func match(pkg *model.Package, vulnerability *model.Vulnerability) bool {
	var matched bool
	if len(vulnerability.Criteria.CPES) > 0 && len(pkg.CPEs) > 0 {
		matched = MatchCPE(pkg, &vulnerability.Criteria)
	}

	if matched {
		return matched
	}

	if checkProductVendor(pkg, vulnerability) && len(vulnerability.Criteria.Constraint) > 0 {
		return MatchConstraint(&pkg.Version, &vulnerability.Criteria)
	}

	return matched
}

// Select all vulnerabilities can be asociated based on the keywords and vendor of the package
func filter(vulnerabilities *[]model.Vulnerability, keywords *[]string) []model.Vulnerability {
	var fv []model.Vulnerability
	for _, v := range *vulnerabilities {
		for _, keyword := range *keywords {
			if strings.EqualFold(v.Package, keyword) {
				fv = append(fv, v)
			}
		}
	}
	return fv
}

func FormResult(vulnerability *model.Vulnerability, pkg *model.Package) model.Result {

	if strings.EqualFold(vulnerability.CVSS.Severity, "UNKNOWN") {
		if strings.EqualFold(vulnerability.CVSS.Method, "2") {
			vulnerability.CVSS.Severity = GetCVSS2Severity(&vulnerability.CVSS.Score)
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
		VersionRange:   vulnerability.Criteria.Constraint,
		CVSS:           vulnerability.CVSS,
		Description:    vulnerability.Description.Content,
		Remediation:    vulnerability.Remediation,
		Reference:      vulnerability.Reference,
	}
}

func GetCVSS2Severity(baseScore *float64) string {
	if *baseScore >= 0.0 && *baseScore <= 3.9 {
		return "LOW"
	}
	if *baseScore >= 4.0 && *baseScore <= 6.9 {
		return "MEDIUM"
	}
	if *baseScore >= 7.0 && *baseScore <= 10.0 {
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
