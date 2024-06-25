package cdx

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/match"
)

func AddVex(matches []match.Found, component cyclonedx.Component, bom *cyclonedx.BOM) {
	if matches == nil {
		return
	}

	for _, m := range matches {
		match, vuln := m.Match, m.Metadata

		vex := cyclonedx.Vulnerability{
			BOMRef: component.BOMRef,
			ID:     vuln.CVE,
		}

		if vuln.References != nil && len(vuln.References) > 0 {
			references := new([]cyclonedx.VulnerabilityReference)
			for _, ref := range vuln.References {
				source := cyclonedx.Source{
					Name: ref.Source,
					URL:  ref.URL,
				}
				*references = append(*references, cyclonedx.VulnerabilityReference{
					Source: &source,
				})
			}
			vex.References = references
		}

		if vuln.Description != "" {
			vex.Description = vuln.Description
		}

		if vuln.CVSS != nil && len(vuln.CVSS) > 0 {
			ratings := new([]cyclonedx.VulnerabilityRating)
			for _, cvss := range vuln.CVSS {
				rating := cyclonedx.VulnerabilityRating{
					Score:  &cvss.Score,
					Method: cyclonedx.ScoringMethod(cvss.Method),
					Vector: cvss.Vector,
					Source: &cyclonedx.Source{
						URL: cvss.Source,
					},
				}
				*ratings = append(*ratings, rating)
			}
			vex.Ratings = ratings
		}

		if vuln.Fixes != nil && len(vuln.Fixes) > 0 {
			recomendation := ""
			for _, fix := range vuln.Fixes {
				recomendation += fmt.Sprintf("Upgrade %s from %s to %s.", component.Name, component.Version, fix.Value)
				if len(vuln.Fixes) > 1 {
					recomendation += "\n"
				}
			}
			vex.Recommendation = recomendation
		}

		if len(m.Constraint) > 0 {
			affects := new([]cyclonedx.Affects)
			affect := new(cyclonedx.Affects)
			affect.Ref = component.BOMRef
			ranges := new([]cyclonedx.AffectedVersions)
			affected := cyclonedx.AffectedVersions{
				Range: m.Constraint,
			}
			*ranges = append(*ranges, affected)
			affect.Range = ranges
			vex.Affects = affects
		}

		if match.Advisories != nil && len(match.Advisories) > 0 {
			advisories := new([]cyclonedx.Advisory)
			for _, a := range match.Advisories {
				advisory := cyclonedx.Advisory{
					Title: a,
				}
				*advisories = append(*advisories, advisory)
			}
			vex.Advisories = advisories
		}

		*bom.Vulnerabilities = append(*bom.Vulnerabilities, vex)
	}
}
