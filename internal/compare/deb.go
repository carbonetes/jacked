package compare

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
	version "github.com/masahiro331/go-mvn-version"
)

const debComparer = "deb-exclusive-comparer"

type debMatcher struct {
	name          string
	version       string
	upstream      string
	component     *cyclonedx.Component
	debSecTracker *[]types.Vulnerability
	// nvd           *[]types.Vulnerability // nvd is not yet used in this comparer since we are still working on the implementation
	matches       *[]match
}

type debConstraint struct {
	operator string
	version  version.Version
}

func newDebConstraint(constraintStr string) (*debConstraint, error) {
	constraintParts, err := parseSingleConstraint(constraintStr)
	if err != nil {
		return nil, err
	}

	version, err := version.NewVersion(constraintParts[2])
	if err != nil {
		return nil, err
	}

	return &debConstraint{
		operator: constraintParts[1],
		version:  version,
	}, nil
}

func (m *comparer) lookUpDebSecTracker() *comparer {
	res := m.store.DebSecTrackerMatchWithKeywords(m.debKeywords)
	for i, pkg := range m.deb {
		vulns := []types.Vulnerability{}
		for _, vuln := range *res {
			if pkg.name == vuln.Package || pkg.upstream == vuln.Package {
				vulns = append(vulns, vuln)
			}
		}
		m.deb[i].debSecTracker = &vulns
	}

	return m
}

func (m *comparer) matchDeb() *comparer {
	if len(m.deb) == 0 {
		return m
	}

	for i, pkg := range m.deb {
		if pkg.debSecTracker == nil {
			continue
		}
		m.deb[i].matches = new([]match)
		for _, v := range *pkg.debSecTracker {
			constraint, matched := compareDebConstraint(pkg.version, v.Constraints)
			if matched {
				*m.deb[i].matches = append(*m.deb[i].matches, match{
					Constraint:    constraint,
					Vulnerability: &v,
				})
			}
		}
	}

	return m
}

// Same stragety as apk with single constraint pattern, but with different version comparison
func compareDebConstraint(packageVersion string, constraints string) (string, bool) {
	pVersion, err := version.NewVersion(packageVersion)
	if err != nil {
		return "", false
	}

	constraintSlice := []string{constraints}
	for _, constraint := range constraintSlice {
		d, err := newDebConstraint(constraint)
		if err != nil {
			return "", false
		}

		if d.compareVersion(pVersion) {
			return constraint, true
		}
	}

	return "", false
}

func (d *debConstraint) compareVersion(packageVersion version.Version) bool {
	compResult := packageVersion.Compare(d.version)
	switch d.operator {
	case "=":
		return compResult == VersionEqual
	case ">":
		return compResult == VersionGreater
	case "<":
		return compResult == VersionLess
	case ">=":
		return compResult == VersionGreater || compResult == VersionEqual
	case "<=":
		return compResult == VersionLess || compResult == VersionEqual
	default:
		return false
	}
}

func (c *comparer) debSecTrackerToVex() *comparer {
	incoming := new([]cyclonedx.Vulnerability)
	for _, pkg := range c.deb {
		if pkg.matches == nil {
			continue
		}

		for _, match := range *pkg.matches {
			vex := &cyclonedx.Vulnerability{
				BOMRef: pkg.component.BOMRef,
				ID:     match.Vulnerability.CVE,
				Affects: &[]cyclonedx.Affects{
					{
						Ref: pkg.component.BOMRef,
						Range: &[]cyclonedx.AffectedVersions{
							{
								Version: pkg.version,
								Range:   match.Constraint,
								Status:  cyclonedx.VulnerabilityStatusAffected,
							},
						},
					},
				},
			}

			// vex.Ratings = &[]cyclonedx.VulnerabilityRating{
			// 	{
			// 		Severity: cyclonedx.Severity(match.Vulnerability.Severity),
			// 	},
			// }

			props := make([]cyclonedx.Property, 0)
			matcher := cyclonedx.Property{
				Name:  packageComparerId,
				Value: debComparer,
			}

			record := cyclonedx.Property{
				Name:  "database:id",
				Value: fmt.Sprintf("%d", match.Vulnerability.ID),
			}

			props = append(props, matcher)
			props = append(props, record)
			vex.Properties = &props

			if len(match.Vulnerability.References) > 0 {
				vex.References = &[]cyclonedx.VulnerabilityReference{}
				for _, ref := range match.Vulnerability.References {
					if ref.Source == "security-tracker.debian.org" {
						vex.Source = &cyclonedx.Source{
							Name: ref.Source,
							URL:  ref.URL,
						}
					}

					*vex.References = append(*vex.References, cyclonedx.VulnerabilityReference{
						ID: vex.ID,
						Source: &cyclonedx.Source{
							Name: ref.Source,
							URL:  ref.URL,
						},
					})
				}
			}

			// ratings := make([]cyclonedx.VulnerabilityRating, 0)
			// rating := cyclonedx.VulnerabilityRating{
			// 	Severity: cyclonedx.Severity(match.Vulnerability.Severity),
			// }
			// ratings = append(ratings, rating)
			// vex.Ratings = &ratings

			vex.Description = match.Vulnerability.Description

			if len(match.Vulnerability.Fixes) > 0 {
				if len(match.Vulnerability.Fixes) == 1 {
					vex.Recommendation = fmt.Sprintf("Upgrade %s to %s", pkg.name, match.Vulnerability.Fixes[0])
				}

				if len(match.Vulnerability.Fixes) > 1 {
					vex.Recommendation = fmt.Sprintf("Upgrade %s to one of the following versions: %s", pkg.name, strings.Join(match.Vulnerability.Fixes, ","))
				}
			}
			if !slices.Contains(*incoming, *vex) {
				*incoming = append(*incoming, *vex)
			}
		}
	}

	c.vex = addVex(c.vex, incoming)
	c.addNVDData()
	return c
}
