package rubygem

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/version"
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

		if helper.GetComponentType(c.Properties) != "gem" {
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

		pkgVersion, err := version.NewGemVersion(c.Version)
		if err != nil {
			return nil, err
		}

		for _, vuln := range *vulns {
			if vuln.Constraints == "" {
				continue
			}

			match, err := pkgVersion.Check(vuln.Constraints)
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
	}
	return results, nil
}
