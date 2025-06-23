package generic

import (
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/version"
	hashicorp "github.com/hashicorp/go-version"
)

type Scanner struct {
	store db.Store
}

// NewScanner creates a new Go scanner with the given db.Store.
func NewScanner(store db.Store) *Scanner {
	return &Scanner{
		store: store,
	}
}

var excludedComponentType = []string{"apk", "dpkg", "gem", "golang", "java", "python", "rpm"}

// Scan scans the generic BOM for vulnerabilities and returns a slice of cyclonedx.Vulnerability.
func (s *Scanner) Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var results []cyclonedx.Vulnerability
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	for _, c := range *bom.Components {
		if c.Properties == nil {
			continue
		}

		if slices.Contains(excludedComponentType, helper.GetComponentType(c.Properties)) {
			continue
		}

		upstream := helper.FindUpstream(c.BOMRef)
		keywords := []string{c.Name}
		if upstream != "" {
			keywords = append(keywords, upstream)
		}

		vulns := s.store.NVDMatchWithPackageNames(keywords)
		if vulns == nil {
			continue
		}

		semVer, err := version.NewSemanticVersion(c.Version)
		if err != nil {
			continue
		}

		for _, vuln := range *vulns {
			if vuln.Constraints == "" {
				continue
			}

			if strings.Contains(vuln.Constraints, " || ") {
				constraints := strings.Split(vuln.Constraints, " || ")
				for _, constraint := range constraints {
					semConstraint, err := hashicorp.NewConstraint(constraint)
					if err != nil {
						log.Debugf("invalid constraint: %s, error: %v", constraint, err)
						continue
					}

					if semConstraint.Check(semVer) {
						vex := v3.ToVex(&vuln, &c, semConstraint.String())
						if vex != nil {
							results = append(results, *vex)
						}
					}

				}
			}
		}
	}

	return results, nil
}
