package python

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/version"
	hashicorp "github.com/hashicorp/go-version"
)

type Scanner struct {
	store db.Store
}

func NewScanner(store db.Store) *Scanner {
	return &Scanner{
		store: store,
	}
}

func (s *Scanner) Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var results []cyclonedx.Vulnerability
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	for _, c := range *bom.Components {
		if c.Properties == nil {
			continue
		}

		if helper.GetComponentType(c.Properties) != "python" {
			continue
		}

		upstream := helper.FindUpstream(c.BOMRef)
		keywords := []string{c.Name}
		if upstream != "" {
			keywords = append(keywords, upstream)
		}

		vulns := s.store.NVDMatchWithKeywords(keywords)
		if vulns == nil {
			continue
		}

		pkgVersion, err := parseVersionFormat(c.Version)
		if err != nil {
			return nil, err
		}

		switch v := pkgVersion.(type) {
		case *version.PEP440Version:
			for _, vuln := range *vulns {
				if vuln.Constraints == "" {
					continue
				}

				match, err := v.Check(vuln.Constraints)
				if err != nil {
					return nil, err
				}

				if match {
					vex := v3.ToVex(&vuln, &c, vuln.Constraints)
					if vex != nil {
						results = append(results, *vex)
					}
				}
			}
		case *hashicorp.Version:
			for _, vuln := range *vulns {
				if vuln.Constraints == "" {
					continue
				}

				constraintSlice := []string{}
				if strings.Contains(vuln.Constraints, " || ") {
					constraintSlice = strings.Split(vuln.Constraints, " || ")
				} else {
					constraintSlice = append(constraintSlice, vuln.Constraints)
				}

				for _, constraint := range constraintSlice {
					constr, err := hashicorp.NewConstraint(constraint)
					if err != nil {
						return nil, err
					}

					if constr.Check(v) {
						vex := v3.ToVex(&vuln, &c, constraint)
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

func parseVersionFormat(versionStr string) (interface{}, error) {
	if len(versionStr) == 0 {
		return nil, version.ErrInvalidVersionFormat
	}

	pep440Ver, err := version.NewPEP440Version(versionStr)
	if err != nil {
		// If PEP440 version creation fails, we can try semantic versioning
		semVer, err := version.NewSemanticVersion(versionStr)
		if err != nil {
			return nil, err
		}
		return semVer, nil
	}
	return pep440Ver, nil
}
