package compare

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
	version "github.com/masahiro331/go-mvn-version"
)

const mavenComparer = "maven-exclusive-comparer"

type mavenMatcher struct {
	name      string
	group     string
	version   string
	component *cyclonedx.Component
	// nvd       *[]types.Vulnerability // nvd is not yet used in this comparer since we are still working on the implementation
	ghsa    *[]types.Vulnerability
	matches *[]match
}

type mavenConstraint struct {
	Operator string
	Version  version.Version
}

func newMavenConstraint(constraintStr string) (*[]mavenConstraint, error) {
	if constraintStr == "" {
		return nil, nil
	}

	mavenConstraints := new([]mavenConstraint)
	if strings.Contains(constraintStr, ",") {
		constraints, err := parseMultiConstraint(constraintStr)
		if err != nil {
			return nil, err
		}

		if constraints == nil {
			return nil, fmt.Errorf("failed to parse constraints")
		}

		for _, constraint := range constraints {
			version, err := version.NewVersion(constraint[2])
			if err != nil {
				return nil, err
			}

			*mavenConstraints = append(*mavenConstraints, mavenConstraint{
				Operator: constraint[1],
				Version:  version,
			})
		}
	} else {
		constraint, err := parseSingleConstraint(constraintStr)
		if err != nil {
			return nil, err
		}

		version, err := version.NewVersion(constraint[2])
		if err != nil {
			return nil, err
		}

		*mavenConstraints = append(*mavenConstraints, mavenConstraint{
			Operator: constraint[1],
			Version:  version,
		})
	}

	return mavenConstraints, nil
}

func (c *comparer) lookUpGhsa() *comparer {
	if len(c.maven) == 0 {
		return c
	}

	res := c.store.GhsaDBMatchByKeywords(c.mavenKeywords)
	for i, pkg := range c.maven {
		vulns := []types.Vulnerability{}
		for _, vuln := range *res {
			if pkg.group == vuln.Package {
				vulns = append(vulns, vuln)
			}
		}
		c.maven[i].ghsa = &vulns
	}

	return c
}

func (c *comparer) matchMaven() *comparer {
	if len(c.maven) == 0 {
		return c
	}

	for i, pkg := range c.maven {
		if pkg.ghsa == nil {
			continue
		}
		c.maven[i].matches = new([]match)
		for _, vuln := range *pkg.ghsa {
			constraint, matched := compareMavenConstraint(pkg.version, vuln.Constraints)
			if matched {
				*c.maven[i].matches = append(*c.maven[i].matches, match{
					Constraint:    constraint,
					Vulnerability: &vuln,
				})
			}
		}
	}

	return c
}

func compareMavenConstraint(packageVersion string, constraintsRaw string) (string, bool) {
	pVersion, err := version.NewVersion(packageVersion)
	if err != nil {
		return "", false
	}

	if strings.Contains(constraintsRaw, " || ") {
		constraints := strings.Split(constraintsRaw, " || ")
		for _, constraint := range constraints {
			mavenConstraints, err := newMavenConstraint(constraint)
			if err != nil {
				return "", false
			}

			if mavenConstraints == nil {
				continue
			}

			if len(*mavenConstraints) == 0 {
				continue
			}

			if len(*mavenConstraints) == 1 {
				if (*mavenConstraints)[0].compareVersion(pVersion) {
					return constraint, true
				}
			}

			if len(*mavenConstraints) == 2 {
				if (*mavenConstraints)[1].compareVersion(pVersion) {
					if (*mavenConstraints)[0].compareVersion(pVersion) {
						return constraint, true
					}
				}
			}
		}
	} else {
		mavenConstraints, err := newMavenConstraint(constraintsRaw)
		if err != nil || mavenConstraints == nil {
			return "", false
		}

		if len(*mavenConstraints) == 0 {
			return "", false
		}

		if len(*mavenConstraints) == 1 {
			if (*mavenConstraints)[0].compareVersion(pVersion) {
				return constraintsRaw, true
			}
		}

		if len(*mavenConstraints) == 2 {
			if (*mavenConstraints)[1].compareVersion(pVersion) {
				if (*mavenConstraints)[0].compareVersion(pVersion) {
					return constraintsRaw, true
				}
			}
		}
	}

	return "", false
}

func (m *mavenConstraint) compareVersion(packageVersion version.Version) bool {
	switch m.Operator {
	case ">":
		return packageVersion.GreaterThan(m.Version)
	case "<":
		return packageVersion.LessThan(m.Version)
	case "=":
		return packageVersion.Equal(m.Version)
	case ">=":
		return packageVersion.GreaterThanOrEqual(m.Version)
	case "<=":
		return packageVersion.LessThanOrEqual(m.Version)
	}

	return false
}

func (c *comparer) mavenToVex() *comparer {
	if len(c.maven) == 0 {
		return c
	}

	incoming := new([]cyclonedx.Vulnerability)
	for _, pkg := range c.maven {
		if pkg.matches == nil {
			continue
		}

		for _, m := range *pkg.matches {
			vex := &cyclonedx.Vulnerability{
				BOMRef:      pkg.component.BOMRef,
				ID:          m.Vulnerability.CVE,
				Description: m.Vulnerability.Description,
				Affects: &[]cyclonedx.Affects{
					{
						Ref: pkg.component.BOMRef,
						Range: &[]cyclonedx.AffectedVersions{
							{
								Version: pkg.version,
								Range:   m.Constraint,
								Status:  cyclonedx.VulnerabilityStatusAffected,
							},
						},
					},
				},
			}

			if len(m.Vulnerability.CVSS) > 0 {
				vex.Ratings = new([]cyclonedx.VulnerabilityRating)
				for _, cvss := range m.Vulnerability.CVSS {
					*vex.Ratings = append(*vex.Ratings, cyclonedx.VulnerabilityRating{
						Score:    &cvss.Score,
						Severity: cyclonedx.Severity(cvss.Severity),
						Vector:   cvss.Vector,
					})
				}
			}

			if len(m.Vulnerability.References) > 0 {
				vex.References = new([]cyclonedx.VulnerabilityReference)
				for _, ref := range m.Vulnerability.References {
					*vex.References = append(*vex.References, cyclonedx.VulnerabilityReference{
						ID: m.Vulnerability.CVE,
						Source: &cyclonedx.Source{
							Name: ref.Source,
							URL:  ref.URL,
						},
					})
				}
			}

			props := make([]cyclonedx.Property, 0)
			matcher := cyclonedx.Property{
				Name:  packageComparerId,
				Value: mavenComparer,
			}

			record := cyclonedx.Property{
				Name:  "database:id",
				Value: fmt.Sprintf("%d", m.Vulnerability.ID),
			}

			props = append(props, matcher)
			props = append(props, record)
			vex.Properties = &props

			if len(m.Vulnerability.Fixes) > 0 {
				if len(m.Vulnerability.Fixes) == 1 {
					vex.Recommendation = fmt.Sprintf("Upgrade %s to %s", pkg.name, m.Vulnerability.Fixes[0])
				}

				if len(m.Vulnerability.Fixes) > 1 {
					vex.Recommendation = fmt.Sprintf("Upgrade %s to one of the following versions: %s", pkg.name, strings.Join(m.Vulnerability.Fixes, ","))
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
