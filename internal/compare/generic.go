package compare

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/Masterminds/semver/v3"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/pkg/types"
)

const (
	packageComparerId = "package-comparer-id"
	genericComparer   = "generic-comparer"
)

type genericMatcher struct {
	name      string
	version   string
	upstream  string
	component *cyclonedx.Component
	nvd       *[]types.Vulnerability
	ghsa      *[]types.Vulnerability
	matches   *[]match
}

type genericConstraint struct {
	constraint string
	version    semver.Version
}

func newGenericConstraint(constraintStr string) (*[]genericConstraint, error) {
	if constraintStr == "" {
		return nil, nil
	}

	genericConstraints := new([]genericConstraint)
	if strings.Contains(constraintStr, ",") {
		constraints, err := parseMultiConstraint(constraintStr)
		if err != nil {
			return nil, err
		}

		if constraints == nil {
			return nil, fmt.Errorf("failed to parse constraints")
		}

		for _, constraint := range constraints {
			version, err := semver.NewVersion(constraint[2])
			if err != nil {
				return nil, err
			}

			*genericConstraints = append(*genericConstraints, genericConstraint{
				constraint: constraint[1],
				version:    *version,
			})
		}
	} else {
		constraint, err := parseSingleConstraint(constraintStr)
		if err != nil {
			return nil, err
		}

		version, err := semver.NewVersion(constraint[2])
		if err != nil {
			return nil, err
		}

		*genericConstraints = append(*genericConstraints, genericConstraint{
			constraint: constraint[1],
			version:    *version,
		})
	}

	return genericConstraints, nil
}

func (c *comparer) lookUpNvd() *comparer {
	if len(c.generic) == 0 {
		return c
	}

	res := c.store.NVDMatchWithKeywords(c.keywords)
	if res == nil {
		return c
	}

	if len(*res) == 0 {
		return c
	}

	for i, pkg := range c.generic {
		vulns := []types.Vulnerability{}
		for _, vuln := range *res {
			if pkg.name == vuln.Package || pkg.upstream == vuln.Package {
				vulns = append(vulns, vuln)
			}
		}
		c.generic[i].nvd = &vulns
	}
	
	return c
}

func (m *comparer) matchGeneric() *comparer {
	if len(m.generic) == 0 {
		return m
	}

	for i, pkg := range m.generic {
		if pkg.nvd == nil {
			continue
		}
		m.generic[i].matches = new([]match)
		for _, vuln := range *pkg.nvd {
			constraint, matched := compareGenericConstraint(pkg.version, vuln.Constraints)
			if matched {
				*m.generic[i].matches = append(*m.generic[i].matches, match{
					Vulnerability: &vuln,
					Constraint:    constraint,
				})
			}
		}
	}

	return m
}

func compareGenericConstraint(packageVersion string, constraints string) (string, bool) {
	pVersion, err := semver.NewVersion(normalizeVersion(packageVersion))
	if err != nil {
		return "", false
	}

	if strings.Contains(constraints, " || ") {
		constraintSlice := strings.Split(constraints, " || ")
		for _, constraint := range constraintSlice {
			genericConstraints, err := newGenericConstraint(constraint)
			if err != nil {
				return "", false
			}

			if genericConstraints == nil {
				continue
			}

			if len(*genericConstraints) == 0 {
				continue
			}

			if len(*genericConstraints) == 1 {
				if (*genericConstraints)[0].compareVersion(pVersion) {
					return constraint, true
				}
			}

			if len(*genericConstraints) == 2 {
				if (*genericConstraints)[1].compareVersion(pVersion) {
					if (*genericConstraints)[0].compareVersion(pVersion) {
						return constraint, true
					}
				}
			}
		}
	}

	return "", false
}

func (g *genericConstraint) compareVersion(version *semver.Version) bool {
	if version == nil {
		return false
	}

	v := g.version
	switch g.constraint {
	case ">":
		return v.GreaterThan(&g.version)
	case ">=":
		return v.GreaterThan(&g.version) || v.Equal(&g.version)
	case "<":
		return v.LessThan(&g.version)
	case "<=":
		return v.LessThan(&g.version) || v.Equal(&g.version)
	case "=":
		return v.Equal(&g.version)
	default:
		return false
	}
}

func (c *comparer) toVex() *comparer {
	incoming := new([]cyclonedx.Vulnerability)
	for _, pkg := range c.generic {
		if pkg.matches == nil {
			continue
		}

		for _, match := range *pkg.matches {
			vex := genericToVex(pkg.component, match.Vulnerability)
			if vex != nil {
				continue
			}

			if !slices.Contains(*incoming, *vex) {
				*incoming = append(*incoming, *vex)
			}
		}

	}
	c.vex = addVex(c.vex, incoming)
	return c
}

func genericToVex(pkg *cyclonedx.Component, vuln *types.Vulnerability) *cyclonedx.Vulnerability {

	// Initialize a new Source object to store information about the vulnerability's source (if available)
	source := new(cyclonedx.Source)
	if len(vuln.References) > 0 {
		for _, ref := range vuln.References {
			source.Name = ref.Source
			source.URL = ref.URL
		}
	}

	// Initialize a new pointer to slice of VulnerabilityRating objects, which will hold all ratings for given vulnerability.
	ratings := new([]cyclonedx.VulnerabilityRating)

	// If a scoring method is available (based on CVSS), add a new VulnerabilityRating struct using it.
	if len(vuln.CVSS) > 0 {
		for _, cvss := range vuln.CVSS {
			var rating cyclonedx.VulnerabilityRating
			rating.Method = cyclonedx.ScoringMethod(cvss.Method)
			rating.Score = &cvss.Score
			rating.Severity = cyclonedx.Severity(cvss.Severity)
			rating.Vector = cvss.Vector
			*ratings = append(*ratings, rating)
		}
	}

	// Create a recommendation string to suggest how to solve the vulnerability (if possible)
	var recommendation string
	if len(vuln.Fixes) > 0 {
		if len(vuln.Fixes) == 1 {
			recommendation = "Upgrade to " + vuln.Fixes[0]
		} else {
			recommendation = "Upgrade to one of the following versions: "
			for i, fix := range vuln.Fixes {
				if i == len(vuln.Fixes)-1 {
					recommendation += fix
				} else {
					recommendation += fix + ", "
				}
			}
		}
	}

	// Initialize a new pointer to slice of Affects objects, which will hold all affected versions for given vulnerability.
	affects := new([]cyclonedx.Affects)
	affect := new(cyclonedx.Affects)
	affect.Ref = pkg.PackageURL + "?id=" + pkg.BOMRef
	ranges := new([]cyclonedx.AffectedVersions)
	// If there are any CPEs or constraints in the vulnerability criteria, add them to the affected versions.
	if len(vuln.CPE) > 0 {
		for _, cpe := range vuln.CPE {
			affected := new(cyclonedx.AffectedVersions)
			affected.Version = cpe
			parts := helper.SplitCpe(cpe)
			if len(parts) > 6 {
				if parts[5] != "*" {
					affected.Status = cyclonedx.VulnerabilityStatusAffected
				} else {
					affected.Status = cyclonedx.VulnerabilityStatusUnknown
				}
			}
			*ranges = append(*ranges, *affected)
		}
	}

	// Add the affected versions to the Affects object.
	affect.Range = new([]cyclonedx.AffectedVersions)
	*affect.Range = append(*affect.Range, *ranges...)
	*affects = append(*affects, *affect)

	props := make([]cyclonedx.Property, 0)
	matcher := cyclonedx.Property{
		Name:  packageComparerId,
		Value: genericComparer,
	}

	record := cyclonedx.Property{
		Name:  "database:id",
		Value: fmt.Sprintf("%d", vuln.ID),
	}

	props = append(props, matcher)
	props = append(props, record)

	// Return a new CycloneDX Vulnerability object initialized with the above data.
	return &cyclonedx.Vulnerability{
		BOMRef:         pkg.BOMRef,
		ID:             vuln.CVE,
		Source:         source,
		Ratings:        ratings,
		Description:    vuln.Description,
		Recommendation: recommendation,
		Affects:        affects,
		Properties:     &props,
	}
}
