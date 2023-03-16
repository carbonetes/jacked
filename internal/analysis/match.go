package analysis

import "github.com/carbonetes/jacked/internal/model"

func FindMatch(pkg model.Package, vulnerabilities []model.Vulnerability) {
	if len(pkg.CPEs) > 0 && len(vulnerabilities) > 0 {
		for _, vulnerability := range vulnerabilities {
			if len(vulnerability.Criteria) > 0 {
				for _, c := range vulnerability.Criteria {
					if len(c.CPES) > 0 && len(pkg.CPEs) > 0 {
						matched, cpe := MatchCPE(pkg.CPEs, c.CPES)
						if matched {

						}
					}
					if len(c.Constraints) > 0 && len(pkg.Version) > 0 {
						matched, packageVersion = MatchConstraint(pkg.Version, c.Constraints)
						
					}
				}
			}
		}
	}
}

func formResult(vulnerability model.Vulnerability, pkg model.Package, versionRange string) model.Result {
	var finalDescription model.Description
	if len(vulnerability.Descriptions) > 0 {
		for _, description := range vulnerability.Descriptions {
			if description.Source ==  "nvd" {
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
        severity = "UNKNOWN"
    }

	return &model.Result{
		CVE: vulnerability.CVE,
		Package: pkg.Name,
		CurrentVersion: pkg.Version,
		VersionRange: versionRange,
		CVSS: finalCVSS,
		Description: finalDescription.Content,
		Remediation: ,
	}
}

// CVE            string      `json:"cve"`
// Package        string      `json:"package"`
// CurrentVersion string      `json:"current_version"`
// VersionRange   string      `json:"version_range"`
// Description    string      `json:"description"`
// CVSS           Cvss        `json:"cvss"`
// Remediation    Remediation `json:"remediation"`
// Reference      Reference   `json:"reference"`