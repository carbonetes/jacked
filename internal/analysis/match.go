package analysis

import (
	"strings"
	"sync"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var WG sync.WaitGroup

func FindMatch(pkg *dm.Package, vulnerabilities *[]model.Vulnerability, signature *model.Signature) {

	if vulnerabilities == nil {
		WG.Done()
		return
	}

	if len(*vulnerabilities) == 0 {
		WG.Done()
		return
	}

	fv := filter(vulnerabilities, &signature.Keywords)

	for _, vulnerability := range *fv {
		matched := match(pkg, &vulnerability, signature)
		if matched {
			if pkg.Vulnerabilities == nil {
				pkg.Vulnerabilities = new([]model.Vulnerability)
			}
			if !exist(pkg.Vulnerabilities, &vulnerability) {
				format(&vulnerability, pkg)
				*pkg.Vulnerabilities = append(*pkg.Vulnerabilities, vulnerability)
			}
		}
	}
	WG.Done()
}

func filter(vulnerabilities *[]model.Vulnerability, keywords *[]string) *[]model.Vulnerability {
	fv := new([]model.Vulnerability)
	for _, v := range *vulnerabilities {
		for _, keyword := range *keywords {
			if strings.EqualFold(v.Package, keyword) {
				*fv = append(*fv, v)
			}
		}
	}
	return fv
}

func match(pkg *dm.Package, vulnerability *model.Vulnerability, signature *model.Signature) bool {
	var matched bool

	// if pkg.Type == "deb" {
	// 	if vulnerability.Criteria.VersionFormat != "debian" {
	// 		return false
	// 	}
	// }

	switch pkg.Type {
	case "go-module":

		if vulnerability.Package == pkg.Name {
			return MatchConstraint(&pkg.Version, &vulnerability.Criteria)
		}

	default:
		if !checkKeywords(signature.Keywords, vulnerability.Package) {
			return matched
		}
		if len(vulnerability.Criteria.CPES) > 0 && len(pkg.CPEs) > 0 {
			matched = MatchCPE(pkg, &vulnerability.Criteria)
		}

		if matched {
			return matched
		}

		return MatchConstraint(&pkg.Version, &vulnerability.Criteria)

	}
	return matched
}

func checkKeywords(keywords []string, vulnPkg string) bool {
	for _, k := range keywords {
		if k == vulnPkg {
			return true
		}
	}
	return false
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
