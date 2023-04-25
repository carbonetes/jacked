package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	build "github.com/carbonetes/jacked/internal/version"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/google/uuid"
)

const (
	cycloneDX        = "CycloneDX"
	vendor           = "carbonetes"
	toolName         = "jacked"
	packagePrefix    = "package"
	distroPrefix     = "distro"
	colonPrefix      = ":"
	cpePrefix        = "cpe23"
	locationPrefix   = "location"
	library          = "library"
	operatingSystem  = "operating-system"
	issueTracker     = "issue-tracker"
	referenceWebsite = "website"
	referenceOther   = "other"
	version          = 1
)

var (
	// XMLN cyclonedx
	XMLN = fmt.Sprintf("http://cyclonedx.org/schema/bom/%+v", cyclonedx.SpecVersion1_4)
)

func ConvertToCycloneDX(results *[]model.ScanResult) *cyclonedx.BOM {

	if len(*results) == 0 {
		return nil
	}

	components := new([]cyclonedx.Component)
	vulnerabilities := new([]cyclonedx.Vulnerability)

	for _, result := range *results {
		*components = append(*components, convertToComponent(&result.Package))
		*vulnerabilities = append(*vulnerabilities, *CreateVex(&result.Package, &result.Vulnerabilities)...)
	}

	*components = append(*components, addDistroComponent(Distro()))

	return &cyclonedx.BOM{
		BOMFormat:       cycloneDX,
		SpecVersion:     cyclonedx.SpecVersion1_4,
		XMLNS:           XMLN,
		SerialNumber:    uuid.NewString(),
		Version:         version,
		Metadata:        getFromSource(),
		Components:      components,
		Vulnerabilities: vulnerabilities,
	}
}

func addDistroComponent(distro *model.Distro) cyclonedx.Component {

	if distro == nil {
		return cyclonedx.Component{}
	}
	var externalReferences []cyclonedx.ExternalReference
	if distro.BugReportURL != "" {
		externalReferences = append(externalReferences, cyclonedx.ExternalReference{
			URL:  distro.BugReportURL,
			Type: issueTracker,
		})
	}
	if distro.HomeURL != "" {
		externalReferences = append(externalReferences, cyclonedx.ExternalReference{
			URL:  distro.HomeURL,
			Type: referenceWebsite,
		})
	}
	if distro.SupportURL != "" {
		externalReferences = append(externalReferences, cyclonedx.ExternalReference{
			URL:     distro.SupportURL,
			Type:    referenceOther,
			Comment: "support",
		})
	}
	if distro.PrivacyPolicyURL != "" {
		externalReferences = append(externalReferences, cyclonedx.ExternalReference{
			URL:     distro.PrivacyPolicyURL,
			Type:    referenceOther,
			Comment: "privacyPolicy",
		})
	}
	properties := make([]cyclonedx.Property, 0)

	//assign id
	properties = append(properties, cyclonedx.Property{
		Name:  toolName + colonPrefix + distroPrefix + ":id",
		Value: distro.ID,
	})

	properties = append(properties, cyclonedx.Property{
		Name:  toolName + colonPrefix + distroPrefix + ":prettyName",
		Value: distro.PrettyName,
	})

	properties = append(properties, cyclonedx.Property{
		Name:  toolName + colonPrefix + distroPrefix + ":distributionCodename",
		Value: distro.DistribCodename,
	})

	properties = append(properties, cyclonedx.Property{
		Name:  toolName + colonPrefix + distroPrefix + ":versionID",
		Value: distro.VersionID,
	})

	return cyclonedx.Component{
		Type:               operatingSystem,
		Name:               distro.ID,
		Description:        distro.PrettyName,
		ExternalReferences: &externalReferences,
		Properties:         &properties,
	}
}

func getFromSource() *cyclonedx.Metadata {
	//temp data-- data should come from final bom model
	versionInfo := build.GetBuild()
	return &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cyclonedx.Tool{
			{
				Vendor:  vendor,
				Name:    toolName,
				Version: versionInfo.Version,
			},
		},
	}
}

func convertToComponent(p *model.Package) cyclonedx.Component {

	var properties []cyclonedx.Property

	//assign type
	properties = append(properties, cyclonedx.Property{
		Name:  toolName + colonPrefix + packagePrefix + ":type",
		Value: p.Type,
	})

	//assign cpes
	for _, cpe := range p.CPEs {
		properties = append(properties, cyclonedx.Property{
			Name:  toolName + colonPrefix + cpePrefix,
			Value: cpe,
		})
	}

	//assign locations
	for i, location := range p.Locations {
		index := strconv.Itoa(i)

		//add hash
		properties = append(properties, cyclonedx.Property{
			Name:  toolName + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + "layerHash",
			Value: location.LayerHash,
		})
		//add path
		properties = append(properties, cyclonedx.Property{
			Name:  toolName + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + "path",
			Value: location.Path,
		})
	}

	return cyclonedx.Component{
		BOMRef:     addID(p),
		Type:       library,
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: string(p.PURL),
		Licenses:   convertLicense(p),
		Properties: &properties,
	}
}

func addID(p *model.Package) string {
	return string(p.PURL) + "?package-id=" + p.ID
}

func convertLicense(p *model.Package) *cyclonedx.Licenses {
	if len(p.Licenses) == 0 {
		return nil
	}

	licenses := new(cyclonedx.Licenses)

	// Get Licenses for CycloneDX model
	for _, license := range p.Licenses {
		license := cyclonedx.License{
			ID: license,
		}
		*licenses = append(*licenses, cyclonedx.LicenseChoice{
			License: &license,
		})
	}

	return licenses
}

func CreateVex(pkg *model.Package, vulnerabilities *[]model.Vulnerability) *[]cyclonedx.Vulnerability {

	if len(*vulnerabilities) == 0 {
		return nil
	}
	metadata := parsePackageMetada(pkg.Metadata)
	vexes := new([]cyclonedx.Vulnerability)

	for _, v := range *vulnerabilities {
		// Retrieve Package Metadata for Source and Description

		*vexes = append(*vexes, cyclonedx.Vulnerability{
			// BOM Reference Format: urn:cdx:serialNumber/version#bom-ref
			BOMRef:         uuid.NameSpaceDNS.URN() + "/1",
			ID:             v.CVE,
			Source:         createSource(v.CVE),
			Ratings:        createRatings(&v.CVSS),
			Description:    metadata.PackageDescription, // Package Description
			Detail:         v.Description.Content,       // Detail - Vulnerability Description
			Recommendation: createRecommendation(&v, pkg),
			Advisories:     createAdvisories(v.CVE),
		})
	}

	return vexes
}

func createRatings(cvss *model.CVSS) *[]cyclonedx.VulnerabilityRating {

	if cvss.Method == "0" || cvss.Method == "" {
		return nil
	}

	var url string

	if len(cvss.Vector) > 0 {
		if cvss.Method == "3.1" {
			url = fmt.Sprintf("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=%s&version=%s", cvss.Vector, cvss.Method)
		}
		if cvss.Method == "2" {
			url = fmt.Sprintf("https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=%s&version=%s", cvss.Vector, cvss.Method)
		}
	}

	ratings := new([]cyclonedx.VulnerabilityRating)
	*ratings = append(*ratings, cyclonedx.VulnerabilityRating{
		Source: &cyclonedx.Source{
			Name: "NVD",
			URL:  url,
		},
		Score:    &cvss.Score,
		Severity: cyclonedx.Severity(cvss.Severity),
		Method:   cyclonedx.ScoringMethod(cvss.Method),
		Vector:   cvss.Vector,
	})
	return ratings
}

func parsePackageMetada(pMetadata interface{}) model.PackageMetadata {

	var packageMetadata model.PackageMetadata
	jsonData, _ := json.Marshal(pMetadata)
	err := json.Unmarshal(jsonData, &packageMetadata)
	if err != nil {
		log.Errorf("Error decoding package metada: %v", err)
	}

	return packageMetadata
}

func createSource(id string) *cyclonedx.Source {

	// NVD as generated source name and url
	cveReg := regexp.MustCompile(`CVE`)
	if cveReg.MatchString(id) {
		return &cyclonedx.Source{
			Name: "NVD",
			URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id),
		}
	}

	ghsaReg := regexp.MustCompile(`GHSA`)
	if ghsaReg.MatchString(id) {
		return &cyclonedx.Source{
			Name: "GHSA",
			URL:  fmt.Sprintf("https://github.com/advisories/%s", id),
		}
	}

	return nil
}

func createAdvisories(id string) *[]cyclonedx.Advisory {
	advisories := new([]cyclonedx.Advisory)

	cveReg := regexp.MustCompile(`CVE`)
	if cveReg.MatchString(id) {
		mitre := &cyclonedx.Advisory{
			Title: "MITRE",
			URL:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", id),
		}
		*advisories = append(*advisories, *mitre)
		nvd := &cyclonedx.Advisory{
			Title: "NVD",
			URL:   fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id),
		}
		*advisories = append(*advisories, *nvd)
	}

	ghsaReg := regexp.MustCompile(`GHSA`)
	if ghsaReg.MatchString(id) {
		ghsa := &cyclonedx.Advisory{
			Title: "GHSA",
			URL:   fmt.Sprintf("https://github.com/advisories/%s", id),
		}
		*advisories = append(*advisories, *ghsa)
	}

	if len(*advisories) > 0 {
		return advisories
	}

	return nil

}

func createRecommendation(vuln *model.Vulnerability, pkg *model.Package) string {
	if vuln.Remediation == nil || len(vuln.Remediation.Fix) == 0 {
		return ""
	}
	recommendation := fmt.Sprintf("Upgrade %s to version %s", pkg.Name, vuln.Remediation.Fix)

	return recommendation
}
