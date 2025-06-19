package apk

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	v3 "github.com/carbonetes/jacked/pkg/model/cdx"
	"github.com/carbonetes/jacked/pkg/version"
)

// apk Scanner implements scan.Scanner for dpkg packages.
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
		if c.Properties == nil || helper.GetComponentType(c.Properties) != "apk" {
			continue
		}

		vulns := s.store.ApkSecDBMatch(c.Name)
		upstream := helper.FindUpstream(c.BOMRef)

		if upstream != "" {
			upstreamVulns := s.store.ApkSecDBMatch(upstream)
			if upstreamVulns != nil {
				if vulns == nil {
					vulns = upstreamVulns
				} else {
					*vulns = append(*vulns, *upstreamVulns...)
				}
			}
		}

		apkVersion, err := version.NewApkVersion(c.Version)
		if err != nil {
			continue
		}

		for _, vuln := range *vulns {
			if vuln.Constraints == "" {
				continue
			}

			match, err := apkVersion.Check(vuln.Constraints)
			if err != nil {
				log.Debugf("error checking apk version %s against constraint %s: %v", c.Version, vuln.Constraints, err)
				continue
			}

			if match {
				if vex := v3.ToVex(&vuln, &c, vuln.Constraints); vex != nil {
					results = append(results, *vex)
				}
			}
		}
	}

	return results, nil
}
