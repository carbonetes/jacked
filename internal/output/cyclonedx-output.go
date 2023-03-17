package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/carbonetes/jacked/internal/version"

	parser "github.com/carbonetes/jacked/internal/parser"

	"github.com/google/uuid"
)

const (
	// SBOM
	vendor                                      = "carbonetes"
	name                                        = "jacked"
	jackedPrefix                                = "jacked"
	packagePrefix                               = "package"
	distroPrefix                                = "distro"
	colonPrefix                                 = ":"
	cpePrefix                                   = "cpe23"
	locationPrefix                              = "location"
	library              model.ComponentLibrary = "library"
	operatingSystem                             = "operating-system"
	issueTracker                                = "issue-tracker"
	referenceWebsite                            = "website"
	referenceOther                              = "other"
	id                                          = ":id"
	prettyName                                  = ":prettyName"
	distributionCodename                        = ":distributionCodename"
	versionID                                   = "versionID"
	support                                     = "support"
	privacyPolicy                               = "privacyPolicy"
	layerHash                                   = "layerHash"
	path                                        = "path"
	packageIdPrefix                             = "?package-id="
	cyclonedx                                   = "CycloneDX"
	// XMLN cyclonedx
	XMLN = "http://cyclonedx.org/schema/bom/1.4"
	// CVSS Method
	OtherMethod   string = "other"
	CVSSv2Method  string = "CVSSv2"
	CVSSv3Method  string = "CVSSv3"
	CVSSv31Method string = "CVSSv31"
	// VEX BOM Version
	vexBOMVersion string = "1"
)

var (
	cdxOutputBOM *model.BOM
	showVex      bool = false
)

func PrintCycloneDX(formatType string, results []model.ScanResult) {

	switch formatType {

	// CycloneDX SBOM Vuln
	case "xml":
		cdxOutputBOM = convertPackage(results)
		result, _ := xml.MarshalIndent(cdxOutputBOM, "", " ")
		fmt.Printf("%+v\n", string(result))
	case "json":
		cdxOutputBOM = convertPackage(results)
		result, _ := json.MarshalIndent(cdxOutputBOM, "", " ")
		fmt.Printf("%+v\n", string(result))

	// CycloneDX VEX
	case "vex-json":
		showVex = true
		cdxOutputBOM = convertPackage(results)
		result, _ := json.MarshalIndent(cdxOutputBOM, "", " ")
		fmt.Printf("%+v\n", string(result))
	case "vex-xml":
		showVex = true
		cdxOutputBOM = convertPackage(results)
		result, _ := xml.MarshalIndent(cdxOutputBOM, "", " ")
		fmt.Printf("%+v\n", string(result))
	default:
		log.Error("Format type not found")
		os.Exit(1)
	}

}

func convertPackage(results []model.ScanResult) *model.BOM {

	// Create BOM component
	components := make([]model.Component, len(results))
	for i, result := range results {
		components[i] = convertToComponent(&result.Package, &result.Vulnerabilities)

	}

	if parser.Distro() != nil {
		components = append(components, addDistroComponent(parser.Distro()))
	}

	return &model.BOM{
		BomFormat:    cyclonedx,
		XMLNS:        XMLN,
		SerialNumber: uuid.NewString(),
		Metadata:     getFromSource(),
		Components:   &components,
		VEX:          parseVexBOM(results),
	}
}

func addDistroComponent(distro *model.Distro) model.Component {

	if distro == nil {
		return model.Component{}
	}
	externalReferences := &[]model.ExternalReference{}
	if distro.BugReportURL != "" {
		*externalReferences = append(*externalReferences, model.ExternalReference{
			URL:  distro.BugReportURL,
			Type: issueTracker,
		})
	}
	if distro.HomeURL != "" {
		*externalReferences = append(*externalReferences, model.ExternalReference{
			URL:  distro.HomeURL,
			Type: referenceWebsite,
		})
	}
	if distro.SupportURL != "" {
		*externalReferences = append(*externalReferences, model.ExternalReference{
			URL:     distro.SupportURL,
			Type:    referenceOther,
			Comment: support,
		})
	}
	if distro.PrivacyPolicyURL != "" {
		*externalReferences = append(*externalReferences, model.ExternalReference{
			URL:     distro.PrivacyPolicyURL,
			Type:    referenceOther,
			Comment: privacyPolicy,
		})
	}
	if len(*externalReferences) == 0 {
		externalReferences = nil
	}
	properties := make([]model.Property, 0)

	// Assign ID
	properties = append(properties, model.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + id,
		Value: distro.ID,
	})
	properties = append(properties, model.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + prettyName,
		Value: distro.PrettyName,
	})
	properties = append(properties, model.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + distributionCodename,
		Value: distro.DistribCodename,
	})
	properties = append(properties, model.Property{
		Name:  jackedPrefix + colonPrefix + distroPrefix + versionID,
		Value: distro.VersionID,
	})

	return model.Component{
		Type:               operatingSystem,
		Name:               distro.ID,
		Description:        distro.PrettyName,
		ExternalReferences: externalReferences,
		Properties:         &properties,
	}
}

func getFromSource() *model.Metadata {
	//temp data-- data should come from final bom model
	versionInfo := version.GetBuild()
	return &model.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]model.Tool{
			{
				Vendor:  vendor,
				Name:    name,
				Version: versionInfo.Version,
			},
		},
	}
}

func convertToComponent(p *model.Package, vulns *[]model.Result) model.Component {

	// Removing Vulnerabilities included inside SBOM Packages
	if showVex {
		vulns = nil
	}

	return model.Component{
		BOMRef:          addID(p),
		Type:            library,
		Name:            p.Name,
		Version:         p.Version,
		PackageURL:      string(p.PURL),
		Vulnerabilities: vulns,
		Licenses:        convertLicense(p),
		Properties:      initProperties(p),
	}
}

func initProperties(p *model.Package) *[]model.Property {
	properties := make([]model.Property, 0)

	// Assign Type
	properties = append(properties, model.Property{
		Name:  jackedPrefix + colonPrefix + cpePrefix,
		Value: p.Type,
	})

	// Assign CPEs
	for _, cpe := range p.CPEs {
		properties = append(properties, model.Property{
			Name:  jackedPrefix + colonPrefix + cpePrefix,
			Value: cpe,
		})
	}

	// Assign Location
	for i, location := range p.Locations {
		index := strconv.Itoa(i)

		// Add Hash
		properties = append(properties, model.Property{
			Name:  jackedPrefix + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + layerHash,
			Value: location.LayerHash,
		})

		//Add Path
		properties = append(properties, model.Property{
			Name:  jackedPrefix + colonPrefix + locationPrefix + colonPrefix + index + colonPrefix + path,
			Value: location.Path,
		})
	}
	return &properties
}

func addID(p *model.Package) string {
	return string(p.PURL) + packageIdPrefix + p.ID
}

func convertLicense(p *model.Package) *[]model.Licensecdx {

	licenses := make([]model.Licensecdx, 0)
	for _, licenseName := range p.Licenses {
		licenses = append(licenses, model.Licensecdx{
			ID: licenseName,
		})
	}
	if len(licenses) > 0 {
		return &licenses
	}

	return nil
}

// Vex Functionality
func parseVexBOM(results []model.ScanResult) []model.VexBOM {

	if !showVex {
		return nil
	}

	vexsBOM := make([]model.VexBOM, 0)
	for _, result := range results {

		p := result.Package

		// Retrieve Package Metadata for Source and Description
		metadata := parsePackageMetada(p.Metadata)

		for _, vuln := range result.Vulnerabilities {
			vexsBOM = append(vexsBOM, model.VexBOM{
				// BOM Reference Format: urn:cdx:serialNumber/version#bom-ref
				BomRef:         uuid.NameSpaceDNS.URN() + "/" + vexBOMVersion,
				ID:             vuln.CVE,
				SourceVEX:      generateSourceVex(vuln.CVE),
				RatingsVEX:     generateRatingsVEX(vuln, metadata),
				CWEs:           nil,
				Description:    hasValue(metadata.PackageDescription), // Package Description
				Detail:         &vuln.Description.Content,             // Detail - Vulnerability Description
				Recommendation: generateRecommendation(vuln, result.Package),
				Reference:      generateReference(vuln.Reference),
				Advisories:     generateAdvisoryVex(vuln.CVE),
				CreatedVEX:     "",
				PublishedVEX:   "",
				UpdatedVEX:     "",
				CreditsVEX:     nil,
				ToolsVEX:       nil,
				AnalysisVEX:    generateAnalysisVEX(vuln.Remediation),
				AffectsVEX: []model.AffectVEX{
					{
						Ref: uuid.NameSpaceDNS.URN() + "/" + vexBOMVersion + "#" + string(p.PURL),
					},
				},
			})
		}
	}

	return vexsBOM
}
func generateRatingsVEX(vuln model.Result, metadata model.PackageMetadata) model.RatingVEX {

	urlCalc := "https://nvd.nist.gov/vuln-metrics/cvss/"
	calcVersion := "v2-calculator?vector="
	vector := strings.Replace(vuln.CVSS.Vector, "CVSS:3.1/", "", 1)
	version := "&.0"

	if vuln.CVSS.Method == "3.1" {
		calcVersion = "v3-calculator?vector="
		version = "&.version=3.1"
	}

	return model.RatingVEX{
		SourceVEX: model.SourceVEX{
			Name: "NVD",
			Url:  urlCalc + calcVersion + vector + version,
		},
		BaseScore: vuln.CVSS.Score,
		Severity:  vuln.CVSS.Severity,
		Method:    cvssMethod(vuln.CVSS.Method),
		Vector:    vector,
	}
}

func hasValue(description string) *string {
	// Returns nil on empty string
	if description != "" {
		return &description
	}
	return nil
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

func generateSourceVex(cveId string) model.SourceVEX {

	// NVD as generated source name and url
	re := regexp.MustCompile(`CVE`)
	if re.MatchString(cveId) {
		return model.SourceVEX{
			Name: "NVD",
			Url:  "https://nvd.nist.gov/vuln/detail/" + cveId,
		}
	}
	return model.SourceVEX{}

}

func generateAdvisoryVex(cveId string) *[]model.AdvisoryVEX {

	// Advisory Sources
	cveAdvisories := []model.AdvisoryVEX{
		{Title: "MITRE", Url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name="},
	}

	//  Generated advisory title and url
	advisories := make([]model.AdvisoryVEX, 0)
	re := regexp.MustCompile(`CVE`)
	if re.MatchString(cveId) {
		for _, cveAdvisory := range cveAdvisories {
			cveAdvisory.Url = cveAdvisory.Url + cveId
			advisories = append(advisories, cveAdvisory)
		}

		return &advisories
	}
	return nil

}

func cvssMethod(version string) string {

	cvssValue, err := strconv.ParseFloat(version, 64)
	if err != nil {
		return ""
	}
	switch cvssValue {
	case 2:
		return CVSSv2Method
	case 3:
		return CVSSv3Method
	case 3.1:
		return CVSSv31Method
	default:
		return OtherMethod
	}
}

func generateAnalysisVEX(remediation model.Remediation) *model.AnalysisVEX {
	if remediation.State != "" {
		return &model.AnalysisVEX{
			State: &remediation.State,
		}
	} else {
		return nil
	}
}

func generateRecommendation(vuln model.Result, _package model.Package) *string {
	var recommendation = make([]string, 0)
	if vuln.Remediation.Fix != "" {
		recommendation = append(recommendation, "Upgrade")
		recommendation = append(recommendation, _package.Name+":"+_package.Vendor)
		recommendation = append(recommendation, "to version")
		recommendation = append(recommendation, vuln.Remediation.Fix)
		recommendationMsg := strings.Join(recommendation, " ")
		return &recommendationMsg
	}
	return nil
}

func generateReference(ref model.Reference) *model.SourceVEX {
	if ref.URL != "" && ref.Source != "" {
		return &model.SourceVEX{
			Name: ref.Source,
			Url:  ref.URL,
		}
	}
	return nil
}
