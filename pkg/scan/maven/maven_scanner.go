package maven

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/pkg/version"
)

type Scanner struct {
	store db.Store
}

// NewScanner creates a new Maven scanner with the given db.Store.
func NewScanner(store db.Store) *Scanner {
	return &Scanner{
		store: store,
	}
}

// Scan scans the Maven BOM for vulnerabilities and returns a slice of cyclonedx.Vulnerability.
func (s *Scanner) Scan(bom *cyclonedx.BOM) ([]cyclonedx.Vulnerability, error) {
	var results []cyclonedx.Vulnerability
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
		return results, nil
	}

	for _, c := range *bom.Components {
		if c.Properties == nil {
			continue
		}

		if helper.GetComponentType(c.Properties) != "java" {
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

		mavenVersion, err := version.NewMavenVersion(c.Version)
		if err != nil {
			continue
		}

		for _, vuln := range *vulns {
			if vuln.Constraints == "" {
				continue
			}

			

		}
	}

	return results, nil
}
