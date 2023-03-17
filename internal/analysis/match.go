package analysis

import (
	"sync"

	"github.com/carbonetes/jacked/internal/model"
)

var WG sync.WaitGroup

func FindMatch(pkg *model.Package, vulnerabilities *[]model.Vulnerability, results *[]model.Result) {

	if len(pkg.CPEs) > 0 && len(*vulnerabilities) > 0 {
		for _, vulnerability := range *vulnerabilities {
			if len(vulnerability.Criteria) > 0 {
				for _, c := range vulnerability.Criteria {
					if len(c.CPES) > 0 && len(pkg.CPEs) > 0 {
						matched, cpe := MatchCPE(pkg.CPEs, c.CPES)
						if matched {
							result := formResult(vulnerability, *pkg, "= "+cpe.Version, c)
							if !contains(results, &result) {
								*results = append(*results, result)
							}
						}
					}
					if len(c.Constraints) > 0 && len(pkg.Version) > 0 {
						matched, constraint := MatchConstraint(pkg.Version, c)
						if matched {
							result := formResult(vulnerability, *pkg, constraint, c)
							if !contains(results, &result) {
								*results = append(*results, result)
							}
						}
					}
				}
			}
		}
	}
	defer WG.Done()
}

func formResult(vulnerability model.Vulnerability, pkg model.Package, versionRange string, criteria model.Criteria) model.Result {
	var finalDescription model.Description
	if len(vulnerability.Descriptions) > 0 {
		for _, description := range vulnerability.Descriptions {
			if description.Source == criteria.Source {
				finalDescription = description
			} else {
				finalDescription = description
			}
		}
	}

	var finalCVSS model.Cvss
	if len(vulnerability.CVSS) > 0 {
		for _, cvss := range vulnerability.CVSS {
			if cvss.Method == "3.1" {
				finalCVSS = cvss
			} else {
				finalCVSS = cvss
				finalCVSS.Severity = GetSeverity(cvss.Score)
			}
		}
	} else {
		finalCVSS.Severity = "UNKNOWN"
	}

	var remediation model.Remediation
	if len(vulnerability.Remediations) > 0 {
		for _, r := range vulnerability.Remediations {
			if r.Scope == criteria.Scope {
				remediation = r
			}
		}
	}

	var reference model.Reference
	if len(vulnerability.References) > 0 {
		for _, r := range vulnerability.References {
			if r.Source == criteria.Scope {
				reference = r
			}
		}
	}

	return model.Result{
		CVE:            vulnerability.CVE,
		Package:        pkg.Name,
		CurrentVersion: pkg.Version,
		VersionRange:   versionRange,
		CVSS:           finalCVSS,
		Description:    finalDescription.Content,
		Remediation:    remediation,
		Reference:      reference,
	}
}

func GetSeverity(baseScore float64) string {
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
