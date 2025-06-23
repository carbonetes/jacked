package npm

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

// NewScanner creates a new NPM scanner with the given db.Store.
func NewScanner(store db.Store) *Scanner {
	return &Scanner{
		store: store,
	}
}

// Scan scans the NPM BOM for vulnerabilities and returns a slice of cyclonedx.Vulnerability.
func (s *Scanner) Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var results []cyclonedx.Vulnerability
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	for _, c := range *bom.Components {
		if c.Properties == nil {
			continue
		}

		if helper.GetComponentType(c.Properties) != "npm" {
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

		pkgVer, err := version.NewNpmVersion(c.Version)
		if err != nil {
			continue
		}

		for _, vuln := range *vulns {
			if vuln.Constraints == "" {
				continue
			}

			match, err := pkgVer.Check(vuln.Constraints)
			if err != nil || !match {
				continue
			}

			vex := v3.ToVex(&vuln, &c, vuln.Constraints)
			if vex != nil {
				results = append(results, *vex)
			}
		}
	}

	return results, nil
}
