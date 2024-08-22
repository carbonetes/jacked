package compare

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/package-url/packageurl-go"
)

type comparer struct {
	apk           []apkMatcher
	deb           []debMatcher
	maven         []mavenMatcher
	generic       []genericMatcher
	apkKeywords   []string
	debKeywords   []string
	mavenKeywords []string
	keywords      []string
	distro        string
	distroVersion string
	store         db.Store
	vex           *[]cyclonedx.Vulnerability
}

type match struct {
	Constraint    string
	Vulnerability *types.Vulnerability
}

func Analyze(bom *cyclonedx.BOM) {
	if bom == nil {
		return
	}

	if bom.Components == nil {
		return
	}

	if len(*bom.Components) == 0 {
		return
	}

	newcomparer().execute(bom)
}

func newcomparer() *comparer {
	return &comparer{
		vex: &[]cyclonedx.Vulnerability{},
	}
}

func (c *comparer) execute(bom *cyclonedx.BOM) {
	c = c.classify(bom.Components)

	// This functionality is used to analyze the exclusive types in sbom.
	// Exclusive types are types that are needed to be analyzed in more controlled manner to avoid any false positives.
	// This function is used to identify such types.
	// The identified exclusive types are:
	// 1. apk
	// 2. deb
	// 3. maven/java
	// 4. os - not yet implemented
	// 5. rpm - not yet implemented
	// 6. nuget - not yet implemented
	// 7. python - not yet implemented
	// 8. go - not yet implemented
	// TODO: implement the rest of the types and run each of them through multiple go routines to speed up the process.
	if len(c.deb) > 0 {
		c = c.lookUpDebSecTracker().matchDeb().debSecTrackerToVex()
	}

	if len(c.apk) > 0 {
		c = c.lookUpApkSecDB().matchApk().apkSecDBToVex()
	}

	if len(c.maven) > 0 {
		c = c.lookUpGhsa().matchMaven().mavenToVex()
	}

	// This functionality is aimed to perform analysis on the BOM components that is outside the scope of the Exclusive Matcher.
	// This is a generic function that will be used to match the generic constraints of a package.
	// Using custom function to normalize constraint and semver (Semantic Version) then compare the package version with the constraints.
	if len(c.generic) > 0 {
		c = c.lookUpNvd().matchGeneric().toVex()
	}

	bom.Vulnerabilities = c.vex
}

// classify each component in the BOM to its respective type and store it in the comparer struct.
func (m *comparer) classify(comps *[]cyclonedx.Component) *comparer {
	if comps == nil {
		return nil
	}

	if len(*comps) == 0 {
		return nil
	}

	// TODO: add more types to the comparer struct and classify the components accordingly when the package type comparer are implemented.
	for _, comp := range *comps {
		switch comp.Type {
		case cyclonedx.ComponentTypeLibrary:
			pkgType, upstream := getPackageTypeAndUpstream(comp.BOMRef)
			switch pkgType {
			case packageurl.TypeApk:
				m.apk = append(m.apk, apkMatcher{
					name:      comp.Name,
					version:   comp.Version,
					upstream:  upstream,
					component: &comp,
				})
				m.apkKeywords = append(m.apkKeywords, comp.Name)
				m.apkKeywords = append(m.apkKeywords, upstream)
			case packageurl.TypeDebian:
				m.deb = append(m.deb, debMatcher{
					name:      comp.Name,
					version:   comp.Version,
					upstream:  upstream,
					component: &comp,
				})
				m.debKeywords = append(m.debKeywords, comp.Name)
				m.debKeywords = append(m.debKeywords, upstream)
			case packageurl.TypeMaven:
				group := comp.Name
				if comp.Group != "" {
					group = comp.Group + ":" + comp.Name
				}
				m.maven = append(m.maven, mavenMatcher{
					name:      comp.Name,
					version:   comp.Version,
					group:     group,
					component: &comp,
				})

				m.mavenKeywords = append(m.mavenKeywords, group)
			default:
				m.generic = append(m.generic, genericMatcher{
					component: &comp,
				})
				m.keywords = append(m.keywords, comp.Name)
				m.keywords = append(m.keywords, upstream)
			}
		case cyclonedx.ComponentTypeOS:
			m.distro = comp.Name
			m.distroVersion = comp.Version
		}
	}

	return m
}

func (c *comparer) addNVDData() {
	cves := []string{}
	v := c.vex

	for _, vuln := range *v {
		cves = append(cves, vuln.ID)
	}

	nvdData := c.store.NVDMatchCVEsWithKeywords(cves)

	for i, vuln := range *v {
		for _, nvd := range *nvdData {
			if vuln.ID == nvd.CVE {
				if (*v)[i].Ratings == nil {
					(*v)[i].Ratings = new([]cyclonedx.VulnerabilityRating)
				}

				if len(nvd.CVSS) == 0 {
					*(*v)[i].Ratings = append(*(*v)[i].Ratings, cyclonedx.VulnerabilityRating{
						Severity: cyclonedx.SeverityUnknown,
					})
					continue
				}

				*(*v)[i].Ratings = append(*(*v)[i].Ratings, cyclonedx.VulnerabilityRating{
					Severity: cyclonedx.Severity(nvd.CVSS[0].Severity),
					Score:    &nvd.CVSS[0].Score,
					Vector:   nvd.CVSS[0].Vector,
					Source: &cyclonedx.Source{
						Name: nvd.CVSS[0].Source,
					},
				})

			}
		}
		if (*v)[i].Ratings == nil {
			(*v)[i].Ratings = new([]cyclonedx.VulnerabilityRating)
			*(*v)[i].Ratings = append(*(*v)[i].Ratings, cyclonedx.VulnerabilityRating{
				Severity: cyclonedx.SeverityUnknown,
			})
		}		
	}
	c.vex = v
}
