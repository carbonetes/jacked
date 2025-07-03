package v3

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/model"
)

func ToVex(vulnerability *model.Vulnerability, component *cyclonedx.Component, constraint string) *cyclonedx.Vulnerability {
	if vulnerability == nil {
		return nil
	}

	vex := &cyclonedx.Vulnerability{
		BOMRef: component.BOMRef,
		ID:     vulnerability.CVE,
		Affects: &[]cyclonedx.Affects{
			{
				Ref: component.BOMRef,
				Range: &[]cyclonedx.AffectedVersions{
					{
						Version: component.Version,
						Range:   constraint,
						Status:  cyclonedx.VulnerabilityStatusAffected,
					},
				},
			},
		},
	}

	ratings := make([]cyclonedx.VulnerabilityRating, 0)
	rating := cyclonedx.VulnerabilityRating{
		Severity: cyclonedx.Severity(vulnerability.Severity),
	}
	ratings = append(ratings, rating)
	vex.Ratings = &ratings

	if len(vulnerability.References) > 0 {
		vex.References = &[]cyclonedx.VulnerabilityReference{}
		for _, ref := range vulnerability.References {
			*vex.References = append(*vex.References, cyclonedx.VulnerabilityReference{
				ID: vex.ID,
				Source: &cyclonedx.Source{
					Name: ref.Source,
					URL:  ref.URL,
				},
			})
		}
	}

	vex.Description = vulnerability.Description

	if len(vulnerability.Fixes) > 0 {
		if len(vulnerability.Fixes) == 1 {
			vex.Recommendation = fmt.Sprintf("Upgrade %s to %s", vulnerability.Package, vulnerability.Fixes[0])
		}

		if len(vulnerability.Fixes) > 1 {
			vex.Recommendation = fmt.Sprintf("Upgrade %s to one of the following versions: %s", vulnerability.Package, strings.Join(vulnerability.Fixes, ","))
		}
	}

	return vex
}
