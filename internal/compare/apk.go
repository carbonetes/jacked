package compare

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/types"
	version "github.com/masahiro331/go-mvn-version"
	"github.com/package-url/packageurl-go"
)

const apkComparer = "apk-exclusive-comparer"

type apkMatcher struct {
	name      string
	version   string
	upstream  string
	component *cyclonedx.Component
	apkSecDB  *[]types.Vulnerability
	nvd       *[]types.Vulnerability // nvd is not yet used in this comparer since we are still working on the implementation
	matches   *[]match
}

type apkConstraint struct {
	operator string
	version  version.Version
}

func newApkConstraint(constraintStr string) (*apkConstraint, error) {
	constraintParts, err := parseSingleConstraint(constraintStr)
	if err != nil {
		return nil, err
	}

	version, err := version.NewVersion(constraintParts[2])
	if err != nil {
		return nil, err
	}

	return &apkConstraint{
		operator: constraintParts[1],
		version:  version,
	}, nil
}

func (m *comparer) lookUpApkSecDB() *comparer {
	if len(m.apk) == 0 {
		return m
	}

	res := m.store.ApkSecDBMatchByKeywords(m.apkKeywords)
	for i, pkg := range m.apk {
		vulns := []types.Vulnerability{}
		for _, vuln := range *res {
			if pkg.name == vuln.Package {
				vulns = append(vulns, vuln)
			}
		}
		m.apk[i].apkSecDB = &vulns
	}

	return m
}

func (c *comparer) matchApk() *comparer {
	if len(c.apk) == 0 {
		return c
	}

	for i, pkg := range c.apk {
		if pkg.apkSecDB == nil {
			continue
		}
		c.apk[i].matches = new([]match)
		for _, vuln := range *pkg.apkSecDB {
			constraint, matched := compareApkConstraint(pkg.version, vuln.Constraints)
			if matched {
				*c.apk[i].matches = append(*c.apk[i].matches, match{
					Constraint:    constraint,
					Vulnerability: &vuln,
				})
			}
		}
	}
	return c
}

func compareApkConstraint(packageVersion string, constraints string) (string, bool) {
	pVersion, err := version.NewVersion(packageVersion)
	if err != nil {
		return "", false
	}

	constraintSlice := []string{constraints}

	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	for _, constraint := range constraintSlice {
		c, err := newApkConstraint(constraint)
		if err != nil {
			return "", false
		}

		if c.compareVersion(pVersion) {
			return constraint, true
		}
	}

	return "", false
}

func (c *apkConstraint) compareVersion(packageVersion version.Version) bool {

	compResult := packageVersion.Compare(c.version)
	switch c.operator {
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

func (c *comparer) apkSecDBToVex() *comparer {
	incoming := new([]cyclonedx.Vulnerability)
	for _, pkg := range c.apk {
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

			vex.Ratings = &[]cyclonedx.VulnerabilityRating{
				{
					Severity: cyclonedx.Severity(match.Vulnerability.Severity),
				},
			}

			props := make([]cyclonedx.Property, 0)
			matcher := cyclonedx.Property{
				Name:  packageComparerId,
				Value: apkComparer,
			}

			record := cyclonedx.Property{
				Name:  "database:id",
				Value: fmt.Sprintf("%d", match.Vulnerability.ID),
			}

			props = append(props, matcher)
			props = append(props, record)
			vex.Properties = &props

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
	return c
}

func getPackageTypeAndUpstream(bomref string) (string, string) {
	purl, err := packageurl.FromString(bomref)
	if err != nil {
		return "", ""
	}

	upstream := ""
	for _, q := range purl.Qualifiers {
		if q.Key == "upstream" {
			upstream = q.Value
			break
		}
	}

	if strings.Contains(upstream, " ") {
		parts := strings.Split(upstream, " ")
		upstream = strings.TrimSpace(parts[0])
	}

	return purl.Type, upstream

}

func parseApkVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		if !strings.HasPrefix(parts[0], "v") {
			parts[0] = "v" + parts[0]
		}
		return strings.Join(parts[:2], ".")
	}

	return version
}
