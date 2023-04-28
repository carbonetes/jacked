package analysis

import (
	"strings"
	"sync"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var WG sync.WaitGroup

func FindMatch(pkg *dm.Package, vulnerabilities *[]model.Vulnerability) *[]model.Vulnerability {

	if vulnerabilities == nil {
		WG.Done()
		return nil
	}
	if len(*vulnerabilities) == 0 {
		WG.Done()
		return nil
	}

	if len(pkg.CPEs) == 0 {
		WG.Done()
		return nil
	}

	var result *[]model.Vulnerability

	for _, vulnerability := range *vulnerabilities {
		matched := match(pkg, &vulnerability)
		if *matched {
			if result == nil {
				result = new([]model.Vulnerability)
			}
			format(&vulnerability, pkg)
			if !exist(result, &vulnerability) {
				*result = append(*result, vulnerability)
			}
		}
	}
	WG.Done()
	return result
}

func match(pkg *dm.Package, vulnerability *model.Vulnerability) *bool {
	matched := new(bool)

	switch pkg.Type {
	case "go-module":

		if vulnerability.Package == pkg.Name {
			return MatchConstraint(&pkg.Version, &vulnerability.Criteria)
		}

	default:
		if vulnerability.Package == pkg.Name {
			if len(vulnerability.Criteria.CPES) > 0 && len(pkg.CPEs) > 0 {
				*matched = MatchCPE(pkg, &vulnerability.Criteria)
			}

			if *matched {
				return matched
			}

			return MatchConstraint(&pkg.Version, &vulnerability.Criteria)
		}

	}
	return matched
}

func format(vulnerability *model.Vulnerability, pkg *dm.Package) {

	if strings.EqualFold(vulnerability.CVSS.Severity, "UNKNOWN") {
		if strings.EqualFold(vulnerability.CVSS.Method, "2") {
			vulnerability.CVSS.Severity = GetCVSS2Severity(&vulnerability.CVSS.Score)
		}
	}

	if len(vulnerability.CVSS.Method) == 0 {
		vulnerability.CVSS.Severity = "UNKNOWN"
	}

	if len(vulnerability.Remediation.Fix) == 0 {
		vulnerability.Remediation = nil
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

func exist(result *[]model.Vulnerability, entry *model.Vulnerability) bool {
	if len(*result) == 0 {
		return false
	}
	for _, r := range *result {
		if r.CVE == entry.CVE && r.Package == entry.Package {
			return true
		}
	}
	return false
}
